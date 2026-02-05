# Test cases for PyArmor obfuscation detection
# These patterns are commonly found in malicious packages using PyArmor

# =============================================================================
# PyArmor Bootstrap Code (main obfuscation wrapper)
# =============================================================================

def test_pyarmor_bootstrap():
    # ruleid: pyarmor
    __pyarmor__(__name__, __file__, b'PY00000000\x00\x03\x0a...')


def test_pyarmor_bootstrap_with_args():
    # ruleid: pyarmor
    __pyarmor__(__name__, __file__, b'\x50\x59\x41\x52\x4d\x4f\x52', 2)


# =============================================================================
# Legacy PyTransform Imports (PyArmor < 8.0)
# =============================================================================

# ruleid: pyarmor
from pytransform import pyarmor_runtime

# ruleid: pyarmor
from pytransform import pyarmor_runtime, get_license_info

# ruleid: pyarmor
import pytransform


def test_pytransform_runtime_call():
    # ruleid: pyarmor
    pyarmor_runtime()


def test_pytransform_runtime_with_path():
    # ruleid: pyarmor
    pyarmor_runtime(__file__)


# =============================================================================
# Modern PyArmor Runtime Imports (PyArmor >= 8.0)
# =============================================================================

# ruleid: pyarmor
from pyarmor_runtime import __pyarmor__

# ruleid: pyarmor
from pyarmor_runtime_007444 import __pyarmor__

# ruleid: pyarmor
from pyarmor_runtime_000000 import __pyarmor__


# =============================================================================
# Armor Enter/Exit Markers (bytecode-level obfuscation markers)
# =============================================================================

def test_armor_enter_marker():
    # These markers wrap encrypted bytecode
    # ruleid: pyarmor
    __armor_enter__ = None


def test_armor_exit_marker():
    # ruleid: pyarmor
    __armor_exit__ = None


def test_pyarmor_enter_marker():
    # ruleid: pyarmor
    __pyarmor_enter__ = "marker"


def test_pyarmor_exit_marker():
    # ruleid: pyarmor
    __pyarmor_exit__ = "marker"


# =============================================================================
# Obfuscation Verification Functions
# =============================================================================

def test_check_armored():
    # ruleid: pyarmor
    if check_armored(my_module):
        print("Code is protected")


def test_check_armored_function():
    # ruleid: pyarmor
    result = check_armored(my_function, another_function)


# ruleid: pyarmor
@assert_armored(protected_module)
def my_protected_function():
    pass


# ruleid: pyarmor
@assert_armored(module1, module2.function)
class ProtectedClass:
    pass


# =============================================================================
# Legitimate Code (should NOT trigger)
# =============================================================================

def test_legitimate_armor_variable():
    # ok: pyarmor
    armor = "knight's protection"
    # ok: pyarmor
    armor_type = "plate"


def test_legitimate_transform():
    # ok: pyarmor
    from sklearn import transform
    # ok: pyarmor
    data_transform = lambda x: x * 2


def test_legitimate_runtime():
    # ok: pyarmor
    runtime_config = {"debug": True}
    # ok: pyarmor
    import runtime_utils


def test_legitimate_pyarmor_string():
    # ok: pyarmor
    docs = "PyArmor is an obfuscation tool"
    # ok: pyarmor
    warning = "This code may be protected with pyarmor"
