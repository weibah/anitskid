"""
Anti-Skid :: Command-Line Interface
Provides a console entry-point for manifest generation.
"""

import argparse
import os
import sys

from anti_skid.manifest import generate_manifest


def generate_manifest_cli(argv=None):
    """CLI entry point: anti-skid-gen"""
    parser = argparse.ArgumentParser(
        description="Anti-Skid Manifest Generator — create the integrity baseline.",
        prog="anti-skid-gen",
    )
    parser.add_argument(
        "root",
        nargs="?",
        default=".",
        help="Project root directory (default: current working directory)",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output path for manifest.json (default: <root>/manifest.json)",
    )
    parser.add_argument(
        "--extensions",
        nargs="+",
        default=[".py", ".pyw", ".pyc", ".pyd", ".so", ".dll"],
        help="File extensions to include (space-separated)",
    )
    parser.add_argument(
        "--exclude-dirs",
        nargs="+",
        default=[
            "__pycache__", ".git", ".svn", ".hg",
            "node_modules", "venv", ".venv", "env",
            "build", "dist", ".tox", ".eggs",
        ],
        help="Directories to exclude (space-separated)",
    )

    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"Error: '{root}' is not a directory.", file=sys.stderr)
        sys.exit(1)

    generate_manifest(
        root_dir=root,
        output_path=args.output,
        extensions=tuple(args.extensions),
        exclude_dirs=tuple(args.exclude_dirs),
    )