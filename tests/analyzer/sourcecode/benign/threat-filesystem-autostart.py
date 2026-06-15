# Legit: `.profile` is an attribute access (CLI/config object), not a shell
# startup dotfile, and open() appears elsewhere. Must NOT trip autostart.
def serve(cli_args, config):
    selected = cli_args.profile or config.profile
    with open(selected.path) as f:
        return f.read()
