"""
Entry point: ``python -m urban_hs`` / ``python -m urban_hs --help``
"""

from urban_hs.cli.main import app as _cli_app

if __name__ == "__main__":
    _cli_app()
