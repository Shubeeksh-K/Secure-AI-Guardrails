"""Run Respan Red Team locally through the configured Respan gateway."""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

from secure_ai.settings import Settings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("redteam-report.json"),
        help="Report path (default: redteam-report.json)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    settings = Settings.from_env()
    settings.require_gateway_key()

    environment = os.environ.copy()
    environment["OPENAI_API_KEY"] = settings.respan_api_key
    environment["OPENAI_BASE_URL"] = settings.respan_base_url

    subprocess.run(
        [
            "respan-redteam",
            "scan",
            "adapter.py",
            "--local",
            "--output",
            str(args.output),
        ],
        check=True,
        env=environment,
    )


if __name__ == "__main__":
    main()
