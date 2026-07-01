#!/usr/bin/env python3
"""TracePort main entry point - supports both GUI and CLI."""

import sys
import os

def main():
    if len(sys.argv) > 1 and sys.argv[1] in ['--gui', '-g']:
        from traceport.gui import main as gui_main
        gui_main()
    elif len(sys.argv) > 1:
        from traceport.cli import main as cli_main
        cli_main()
    else:
        from traceport.gui import main as gui_main
        gui_main()

if __name__ == "__main__":
    main()
