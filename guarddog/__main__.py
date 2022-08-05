"""Default execution entry point if running the package via python -m."""

import sys

import pysecurity.cli


def cli():
    """Run pysecurity from script entry point"""
    return pysecurity.cli.cli()

if __name__ == '__main__':
    sys.exit(cli())