"""
JSON-aware check for the threat-npm-http-dependency rule.

The YARA rule of the same name only selects candidate package.json files (it
fires on any quoted http:// or https:// string). This module decides which of
those URLs are dependency specifiers: string values of entries in the top-level
dependencies, devDependencies, optionalDependencies and peerDependencies maps.

The manifest is walked once with the standard library JSON scanner, keeping the
raw token of every dependency value. Each raw value token is classified with
the same patterns the regex-only rule applied to the file text:
  * a plain http:// URL,
  * an http:// or https:// URL whose host is an IPv4 address,
  * an http:// or https:// URL ending in .tar.gz, .tgz or .zip.
Classifying the token as written keeps exactly the URL forms that were reported
before: escapes after the scheme (e.g. "http://host/\\u0061") are still
reported, while an escaped scheme (e.g. "http:\\/\\/host") still is not.

Manifests whose dependency structure cannot be read unambiguously are returned
as problems instead of being treated as clean.
"""

import json
import re
from dataclasses import dataclass, field as dataclass_field
from typing import Callable, List, Set

RULE_ID = "threat-npm-http-dependency"

DEPENDENCY_FIELDS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)

_UTF8_BOM = b"\xef\xbb\xbf"

# Patterns of the previous regex-only rule, applied to one raw string token
# (opening quote included).
_PLAIN_HTTP = re.compile(r'"http://[^"]+"')
_IP_HOST = re.compile(r'"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', re.IGNORECASE)
_ARCHIVE = re.compile(r'"https?://[^"]+\.(tar\.gz|tgz|zip)"', re.IGNORECASE)

_WHITESPACE = re.compile(r"[ \t\n\r]*")
_decoder = json.JSONDecoder()
_scanstring = json.decoder.scanstring  # type: ignore[attr-defined]


def is_suspicious_token(raw_token: str) -> bool:
    """raw_token is a JSON string token as written, including its quotes."""
    return bool(
        _PLAIN_HTTP.match(raw_token)
        or _IP_HOST.match(raw_token)
        or _ARCHIVE.match(raw_token)
    )


@dataclass
class DependencyUrl:
    field: str
    name_token: str  # dependency name as written, with quotes
    url_token: str  # URL as written, without quotes
    char_offset: int  # index of the URL in the decoded manifest text

    def describe(self) -> str:
        return f"{self.field}[{self.name_token}] -> {self.url_token}"


@dataclass
class ManifestCheck:
    urls: List[DependencyUrl] = dataclass_field(default_factory=list)
    problems: List[str] = dataclass_field(default_factory=list)
    text: str = ""
    bom_length: int = 0

    def byte_offset(self, dependency: DependencyUrl) -> int:
        """Byte offset of a dependency URL in the original file."""
        prefix = self.text[: dependency.char_offset]
        return self.bom_length + len(prefix.encode("utf-8"))


class _Walker:
    """Single pass over the top level of a manifest and its dependency maps."""

    def __init__(self, text: str, check: ManifestCheck) -> None:
        self.text = text
        self.check = check

    def _skip_ws(self, idx: int) -> int:
        match = _WHITESPACE.match(self.text, idx)
        return match.end() if match else idx

    def _expect(self, idx: int, char: str) -> int:
        idx = self._skip_ws(idx)
        if self.text[idx : idx + 1] != char:
            raise json.JSONDecodeError(f"Expecting '{char}'", self.text, idx)
        return idx + 1

    def _string(self, idx: int):
        """Decode the string token at idx; return (value, raw token, end)."""
        if self.text[idx : idx + 1] != '"':
            raise json.JSONDecodeError(
                "Expecting property name enclosed in double quotes", self.text, idx
            )
        value, end = _scanstring(self.text, idx + 1, True)
        return value, self.text[idx:end], end

    def _object(self, idx: int, on_member: Callable[[str, str, int], int]) -> int:
        """
        Walk the object whose "{" is at idx. on_member(key, raw key token, value
        start) must consume the member value and return the index after it.
        Return the index after the closing "}".
        """
        idx = self._skip_ws(idx + 1)
        if self.text[idx : idx + 1] == "}":
            return idx + 1
        while True:
            key, raw_key, idx = self._string(self._skip_ws(idx))
            idx = self._skip_ws(self._expect(idx, ":"))
            idx = self._skip_ws(on_member(key, raw_key, idx))
            char = self.text[idx : idx + 1]
            if char == "}":
                return idx + 1
            if char != ",":
                raise json.JSONDecodeError("Expecting ',' delimiter", self.text, idx)
            idx += 1

    def _skip_value(self, idx: int):
        return _decoder.raw_decode(self.text, idx)

    def run(self) -> None:
        start = self._skip_ws(0)
        if self.text[start : start + 1] != "{":
            end = self._skip_ws(self._skip_value(start)[1])  # raises if not JSON
            if end != len(self.text):
                raise json.JSONDecodeError("Extra data", self.text, end)
            self.check.problems.append("top level is not a JSON object")
            return

        seen_fields: Set[str] = set()
        duplicate_fields: Set[str] = set()

        def top_level_member(key: str, raw_key: str, idx: int) -> int:
            if key not in DEPENDENCY_FIELDS:
                return self._skip_value(idx)[1]
            if key in seen_fields:
                duplicate_fields.add(key)
                self.check.problems.append(f"{key} is defined more than once")
            seen_fields.add(key)
            if self.text[idx : idx + 1] != "{":
                end = self._skip_value(idx)[1]
                self.check.problems.append(f"{key} is not an object")
                return end
            return self._dependency_map(key, idx)

        end = self._skip_ws(self._object(start, top_level_member))
        if end != len(self.text):
            raise json.JSONDecodeError("Extra data", self.text, end)
        if duplicate_fields:
            self.check.urls = [
                dependency
                for dependency in self.check.urls
                if dependency.field not in duplicate_fields
            ]

    def _dependency_map(self, field: str, idx: int) -> int:
        seen_names: Set[str] = set()
        urls: dict[str, DependencyUrl] = {}

        def entry(name: str, raw_name: str, value_idx: int) -> int:
            duplicate = name in seen_names
            if duplicate:
                self.check.problems.append(
                    f"{field}[{raw_name}] is defined more than once"
                )
                urls.pop(name, None)
            seen_names.add(name)
            if self.text[value_idx : value_idx + 1] != '"':
                end = self._skip_value(value_idx)[1]
                self.check.problems.append(f"{field}[{raw_name}] is not a string")
                return end
            _, raw_value, end = self._string(value_idx)
            if not duplicate and is_suspicious_token(raw_value):
                urls[name] = DependencyUrl(
                    field=field,
                    name_token=raw_name,
                    url_token=raw_value[1:-1],
                    char_offset=value_idx + 1,
                )
            return end

        end = self._object(idx, entry)
        self.check.urls.extend(urls.values())
        return end


def check_manifest(raw: bytes) -> ManifestCheck:
    """
    Find dependency URLs in the raw bytes of a package.json.

    URLs are returned in file order. Problems describe why (part of) the manifest
    could not be checked. Any parser limit (malformed JSON, an integer above the
    interpreter's digit limit, nesting deeper than the recursion limit) is
    reported as a problem for this file only; URLs found in well-formed
    dependency maps are still returned when only part of the manifest is wrong.
    A duplicate dependency field excludes findings from that entire field.
    A duplicate dependency name excludes findings for that name in its map.
    """
    check = ManifestCheck()
    if raw.startswith(_UTF8_BOM):
        check.bom_length = len(_UTF8_BOM)
    try:
        check.text = raw[check.bom_length :].decode("utf-8")
    except UnicodeDecodeError as e:
        check.problems.append(f"not valid UTF-8 ({e.reason} at byte {e.start})")
        return check

    try:
        _Walker(check.text, check).run()
    except json.JSONDecodeError as e:
        check.urls = []
        check.problems.append(f"not valid JSON ({e.msg} at line {e.lineno})")
    except RecursionError:
        check.urls = []
        check.problems.append("could not be parsed (nesting too deep)")
    except ValueError as e:
        check.urls = []
        check.problems.append(f"could not be parsed ({e})")
    return check
