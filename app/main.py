"""app/main.py — console-script entry point for peerc / pchat (Phase 38).

`python -m app.main` and (after the entry-point switch) the installed
`peerc` and `pchat` commands start here.
"""

import argparse

from app.ui.app import ChatApp
from core.logging_setup import configure_logging


def main() -> None:
    """CLI entrypoint for peerc."""
    parser = argparse.ArgumentParser(prog="peerc", description="Peer-to-peer encrypted chat")
    parser.add_argument(
        "--diagnostic", action="store_true",
        help="Enable INFO-level diagnostic logging to ~/.peerc/diagnostics.log for this run",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable DEBUG-level diagnostic logging for this run (opt-in, single run only)",
    )
    args = parser.parse_args()
    configure_logging(diagnostic_mode=args.diagnostic, debug=args.debug)

    app = ChatApp()
    app._diagnostic_mode = args.debug or args.diagnostic
    app.run()


if __name__ == "__main__":
    main()
