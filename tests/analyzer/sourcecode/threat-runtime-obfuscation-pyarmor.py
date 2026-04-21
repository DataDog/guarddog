# Test cases for PyArmor YARA rule detection
# All patterns below should trigger the threat-runtime-obfuscation-pyarmor rule

# =============================================================================
# PyArmor Bootstrap Code (main obfuscation wrapper)
# =============================================================================

def test_pyarmor_bootstrap():
    __pyarmor__(__name__, __file__, b'PY00000000\x00\x03\x0a...')


def test_pyarmor_bootstrap_with_args():
    __pyarmor__(__name__, __file__, b'\x50\x59\x41\x52\x4d\x4f\x52', 2)


# =============================================================================
# Legacy PyTransform Imports (PyArmor < 8.0)
# =============================================================================

from pytransform import pyarmor_runtime

from pytransform import pyarmor_runtime, get_license_info

import pytransform


def test_pytransform_runtime_call():
    pyarmor_runtime()


def test_pytransform_runtime_with_path():
    pyarmor_runtime(__file__)


# =============================================================================
# Modern PyArmor Runtime Imports (PyArmor >= 8.0)
# =============================================================================

from pyarmor_runtime import __pyarmor__

from pyarmor_runtime_007444 import __pyarmor__

from pyarmor_runtime_000000 import __pyarmor__


# =============================================================================
# Armor Enter/Exit Markers (bytecode-level obfuscation markers)
# =============================================================================

def test_armor_enter_marker():
    __armor_enter__ = None


def test_armor_exit_marker():
    __armor_exit__ = None


def test_pyarmor_enter_marker():
    __pyarmor_enter__ = "marker"


def test_pyarmor_exit_marker():
    __pyarmor_exit__ = "marker"


# =============================================================================
# Obfuscation Verification Functions
# =============================================================================

def test_check_armored():
    if check_armored(my_module):
        print("Code is protected")


def test_check_armored_function():
    result = check_armored(my_function, another_function)


@assert_armored(protected_module)
def my_protected_function():
    pass


@assert_armored(module1, module2.function)
class ProtectedClass:
    pass
