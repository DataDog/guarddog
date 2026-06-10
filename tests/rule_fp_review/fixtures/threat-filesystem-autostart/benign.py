# FALSE POSITIVE: botocore AWS named-profile handling stores a config key whose
# name embeds the profile dotfile token, and open() appears elsewhere in the
# module, so the rule fired without any shell-startup persistence.
PROFILE_CONFIG_KEY = ".profile_config"

def load_profile(path):
    with open(path) as f:
        return f.read()
