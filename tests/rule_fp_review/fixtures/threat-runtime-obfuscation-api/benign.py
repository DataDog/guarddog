# FALSE POSITIVE: the canonical six.py Python 2/3 compatibility shim. `exec` is a
# keyword in Py2 so it must be fetched via getattr; this is legitimate compat code.
import moves
exec_ = getattr(moves.builtins, "exec")
