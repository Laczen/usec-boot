#!/usr/bin/env python3

import click
from . import genkeys
from . import genimage
from . import genrootpkeyinclude

@click.group()
def cli():
    """USECBoot Tool - Unified command line interface for firmware signing tools"""
    pass

# Register all the commands
cli.add_command(genkeys.main, name="genkeys")
cli.add_command(genimage.main, name="genimage")
cli.add_command(genrootpkeyinclude.main, name="genrootpkeyinclude")

if __name__ == '__main__':
    cli()