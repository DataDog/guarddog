# Legitimate code that should NOT trigger threat-runtime-keylogging

# UI framework keyboard event type definitions
class KeyEvent:
    KeyDown: int = 1
    KeyUp: int = 2

KEY_EVENT_RECORD = [
    ("KeyDown", "c_long"),
    ("KeyUp", "c_long"),
]

# HTML event attribute lists
EVENT_ATTRIBUTES = [
    'onfocus', 'onkeydown', 'onkeypress', 'onkeyup', 'onload',
    'onmousedown', 'onmouseup', 'onclick',
]

# Test methods with "capture" and "key" in unrelated contexts
class TestFeatureFlags:
    def test_capture_with_send_feature_flags_flag_keys_filter(self):
        pass

    def test_basic_capture_with_project_api_key(self):
        pass

# Documentation about API keys (not keylogging)
unused_keys = set(captured_kwargs).difference(set(valid_processor_keys))
