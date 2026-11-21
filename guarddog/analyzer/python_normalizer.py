"""AST-based normalization for Python source code before YARA scanning.

Rewrites statically resolvable ``getattr(obj, <const-str>)`` calls into direct
attribute accesses (``obj.attr``) while preserving original line numbers so
source-code YARA rules detect obfuscated capability/threat calls such as
``getattr(requests, "ge" + "t")(...)`` or
``getattr(os, chr(115) + ...)(...)``.
"""

import ast
import keyword
from typing import Dict, List, Optional, Set, Tuple

# Upper bounds to keep preprocessing fast and safe on adversarial inputs.
_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_EVAL_DEPTH = 32
_MAX_ATTR_LEN = 256

_PYTHON_EXTENSIONS = (".py", ".pyx", ".pyi", ".pth")


def is_python_source(file_path: str) -> bool:
    """Return True if *file_path* has a Python source extension."""
    return file_path.lower().endswith(_PYTHON_EXTENSIONS)


def _eval_const_int(node: ast.expr, depth: int = 0) -> Optional[int]:
    """Evaluate a side-effect-free constant integer AST expression."""
    if depth > _MAX_EVAL_DEPTH:
        return None

    if (
        isinstance(node, ast.Constant)
        and isinstance(node.value, int)
        and not isinstance(node.value, bool)
    ):
        return node.value

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        val = _eval_const_int(node.operand, depth + 1)
        if val is None:
            return None
        return -val if isinstance(node.op, ast.USub) else val

    if isinstance(node, ast.BinOp) and isinstance(
        node.op, (ast.Add, ast.Sub, ast.BitXor)
    ):
        left = _eval_const_int(node.left, depth + 1)
        right = _eval_const_int(node.right, depth + 1)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        return left ^ right

    return None


def _eval_chr_call(node: ast.Call, depth: int) -> Optional[str]:
    """Evaluate ``chr(<const-int>)``."""
    if (
        isinstance(node.func, ast.Name)
        and node.func.id == "chr"
        and len(node.args) == 1
        and not node.keywords
    ):
        codepoint = _eval_const_int(node.args[0], depth + 1)
        if codepoint is not None and 0 <= codepoint <= 0x10FFFF:
            return chr(codepoint)
    return None


def _eval_const_str_iterable(node: ast.expr, depth: int) -> Optional[List[str]]:
    """Evaluate a constant iterable of strings (used by ``str.join``)."""
    if depth > _MAX_EVAL_DEPTH:
        return None

    if isinstance(node, (ast.List, ast.Tuple)):
        if len(node.elts) > _MAX_ATTR_LEN:
            return None
        parts: List[str] = []
        for elt in node.elts:
            val = _eval_const_str(elt, depth + 1)
            if val is None:
                return None
            parts.append(val)
        return parts

    # map(chr, [103, 101, 116])
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "map"
        and len(node.args) == 2
        and not node.keywords
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "chr"
        and isinstance(node.args[1], (ast.List, ast.Tuple))
    ):
        if len(node.args[1].elts) > _MAX_ATTR_LEN:
            return None
        chars: List[str] = []
        for elt in node.args[1].elts:
            cp = _eval_const_int(elt, depth + 1)
            if cp is None or not (0 <= cp <= 0x10FFFF):
                return None
            chars.append(chr(cp))
        return chars

    # [chr(c) for c in [103, 101, 116]] / (chr(c) for c in (...))
    if isinstance(node, (ast.ListComp, ast.GeneratorExp)) and len(node.generators) == 1:
        gen = node.generators[0]
        if (
            not gen.ifs
            and not gen.is_async
            and isinstance(gen.target, ast.Name)
            and isinstance(gen.iter, (ast.List, ast.Tuple))
            and isinstance(node.elt, ast.Call)
            and isinstance(node.elt.func, ast.Name)
            and node.elt.func.id == "chr"
            and len(node.elt.args) == 1
            and not node.elt.keywords
            and isinstance(node.elt.args[0], ast.Name)
            and node.elt.args[0].id == gen.target.id
        ):
            if len(gen.iter.elts) > _MAX_ATTR_LEN:
                return None
            comp_chars: List[str] = []
            for elt in gen.iter.elts:
                cp = _eval_const_int(elt, depth + 1)
                if cp is None or not (0 <= cp <= 0x10FFFF):
                    return None
                comp_chars.append(chr(cp))
            return comp_chars

    # reversed("teg") or reversed(["t", "e", "g"])
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "reversed"
        and len(node.args) == 1
        and not node.keywords
    ):
        arg_str = _eval_const_str(node.args[0], depth + 1)
        if arg_str is not None:
            return list(reversed(arg_str))
        arg_list = _eval_const_str_iterable(node.args[0], depth + 1)
        if arg_list is not None:
            return list(reversed(arg_list))

    return None


def _eval_const_str(node: ast.expr, depth: int = 0) -> Optional[str]:
    """Evaluate a side-effect-free constant string AST expression."""
    if depth > _MAX_EVAL_DEPTH:
        return None

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value if len(node.value) <= _MAX_ATTR_LEN else None

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _eval_const_str(node.left, depth + 1)
        right = _eval_const_str(node.right, depth + 1)
        if left is None or right is None:
            return None
        if len(left) + len(right) > _MAX_ATTR_LEN:
            return None
        return left + right

    if isinstance(node, ast.Call):
        ch = _eval_chr_call(node, depth)
        if ch is not None:
            return ch

        # "<sep>".join(...)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "join"
            and len(node.args) == 1
            and not node.keywords
        ):
            sep = _eval_const_str(node.func.value, depth + 1)
            if sep is not None:
                items = _eval_const_str_iterable(node.args[0], depth + 1)
                if items is not None:
                    joined = sep.join(items)
                    return joined if len(joined) <= _MAX_ATTR_LEN else None

        return None

    # "teg"[::-1]
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
        base = _eval_const_str(node.value, depth + 1)
        if base is None:
            return None
        lower: Optional[int] = None
        upper: Optional[int] = None
        step: Optional[int] = None
        if node.slice.lower is not None:
            lower = _eval_const_int(node.slice.lower, depth + 1)
            if lower is None:
                return None
        if node.slice.upper is not None:
            upper = _eval_const_int(node.slice.upper, depth + 1)
            if upper is None:
                return None
        if node.slice.step is not None:
            step = _eval_const_int(node.slice.step, depth + 1)
            if step is None or step == 0:
                return None
        sliced = base[slice(lower, upper, step)]
        return sliced if len(sliced) <= _MAX_ATTR_LEN else None

    # f"{'ge'}{'t'}"
    if isinstance(node, ast.JoinedStr):
        pieces: List[str] = []
        total = 0
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                piece: Optional[str] = part.value
            elif (
                isinstance(part, ast.FormattedValue)
                and part.conversion == -1
                and part.format_spec is None
            ):
                piece = _eval_const_str(part.value, depth + 1)
            else:
                return None
            if piece is None:
                return None
            total += len(piece)
            if total > _MAX_ATTR_LEN:
                return None
            pieces.append(piece)
        return "".join(pieces)

    return None


def _is_getattr_func(func: ast.expr) -> bool:
    """Return True if *func* refers to ``getattr`` or ``builtins.getattr``."""
    if isinstance(func, ast.Name) and func.id == "getattr":
        return True
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "getattr"
        and isinstance(func.value, ast.Name)
        and func.value.id in ("builtins", "__builtins__")
    ):
        return True
    return False


def _node_byte_span(node: ast.expr, line_starts: List[int]) -> Optional[Tuple[int, int]]:
    """Return the (start, end) UTF-8 byte offsets of *node* in the source."""
    if node.end_lineno is None or node.end_col_offset is None:
        return None
    if node.lineno < 1 or node.end_lineno < 1 or node.end_lineno >= len(line_starts):
        return None
    start = line_starts[node.lineno - 1] + node.col_offset
    end = line_starts[node.end_lineno - 1] + node.end_col_offset
    if start < 0 or end < start:
        return None
    return (start, end)


def _needs_parens_for_attr(node: ast.expr) -> bool:
    """Return True if *node* requires parentheses before ``.attr``."""
    return not isinstance(node, (ast.Name, ast.Attribute, ast.Call, ast.Subscript))


def normalize_python_source(source: bytes) -> Optional[bytes]:
    """Rewrite statically resolvable ``getattr`` calls in Python *source*.

    Returns normalized UTF-8 bytes with line numbers preserved when at least
    one ``getattr`` expression was rewritten, or ``None`` if no rewrites apply
    (or the file cannot be parsed).
    """
    if len(source) > _MAX_FILE_BYTES or b"getattr" not in source:
        return None

    utf8_bytes = source.decode("utf-8", errors="replace").encode("utf-8")
    try:
        tree = ast.parse(utf8_bytes)
    except (SyntaxError, ValueError, RecursionError):
        return None

    line_starts: List[int] = [0]
    for line in utf8_bytes.splitlines(keepends=True):
        line_starts.append(line_starts[-1] + len(line))

    # Track Call nodes that are immediately invoked (e.g. getattr(m, "f", d)()),
    # so 3-arg getattr is only normalized when called rather than used as a
    # passive existence check like getattr(obj, "attr", None).
    invoked_calls: Set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Call):
            invoked_calls.add(id(node.func))

    # Collect rewritable getattr calls keyed by their byte span.
    rewrites: Dict[Tuple[int, int], Tuple[ast.expr, str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or node.keywords:
            continue
        if not _is_getattr_func(node.func):
            continue
        if len(node.args) == 2:
            pass
        elif len(node.args) == 3 and id(node) in invoked_calls:
            pass
        else:
            continue
        if any(isinstance(arg, ast.Starred) for arg in node.args):
            continue

        attr_name = _eval_const_str(node.args[1])
        if (
            attr_name is None
            or not attr_name.isidentifier()
            or keyword.iskeyword(attr_name)
        ):
            continue

        span = _node_byte_span(node, line_starts)
        if span is None:
            continue
        rewrites[span] = (node.args[0], attr_name)

    if not rewrites:
        return None

    # Sort spans outer-first (ascending start, descending end) so we can render
    # nested getattr expressions recursively and apply only top-level spans.
    sorted_spans = sorted(rewrites.keys(), key=lambda s: (s[0], -s[1]))

    def _render_slice(slice_start: int, slice_end: int) -> bytes:
        """Render utf8_bytes[slice_start:slice_end] with nested rewrites."""
        out: List[bytes] = []
        cursor = slice_start
        for span_start, span_end in sorted_spans:
            if span_start < cursor:
                continue
            if span_end > slice_end:
                continue
            if span_start == slice_start and span_end == slice_end:
                continue
            out.append(utf8_bytes[cursor:span_start])
            out.append(_render_getattr((span_start, span_end), preserve_lines=False))
            cursor = span_end
        out.append(utf8_bytes[cursor:slice_end])
        return b"".join(out)

    def _render_getattr(span: Tuple[int, int], preserve_lines: bool) -> bytes:
        span_start, span_end = span
        target_node, attr_name = rewrites[span]
        target_span = _node_byte_span(target_node, line_starts)
        if target_span is None:
            return utf8_bytes[span_start:span_end]

        if target_span in rewrites:
            rendered_target = _render_getattr(target_span, preserve_lines=False)
        else:
            rendered_target = _render_slice(target_span[0], target_span[1])

        if _needs_parens_for_attr(target_node) and target_span not in rewrites:
            rendered_target = b"(" + rendered_target + b")"

        replacement = rendered_target + b"." + attr_name.encode("utf-8")

        if preserve_lines:
            orig_newlines = utf8_bytes[span_start:span_end].count(b"\n")
            repl_newlines = replacement.count(b"\n")
            if orig_newlines > repl_newlines:
                # Prepend missing newlines so the rewritten attribute access
                # stays contiguous with any trailing `(` while keeping all
                # subsequent line numbers identical to the original file.
                replacement = b"\n" * (orig_newlines - repl_newlines) + replacement

        return replacement

    # Emit top-level non-overlapping rewrites.
    chunks: List[bytes] = []
    cursor = 0
    for span in sorted_spans:
        span_start, span_end = span
        if span_start < cursor:
            continue
        chunks.append(utf8_bytes[cursor:span_start])
        chunks.append(_render_getattr(span, preserve_lines=True))
        cursor = span_end
    chunks.append(utf8_bytes[cursor:])
    return b"".join(chunks)
