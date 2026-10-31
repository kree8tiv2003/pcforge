"""Entry point for the packaged PCForge.exe (opens the app window)."""
import sys

from pcforge import cli, gui

if __name__ == "__main__":
    if len(sys.argv) > 1:
        sys.exit(cli.main())
    gui.run()
