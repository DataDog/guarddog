"""Default execution entry point if running the package via python -m."""

import sys

import guarddog.cli


def cli():
    """Run guarddog from script entry point"""
    return guarddog.cli.cli()


if __name__ == "__main__":
    sys.exit(cli())
