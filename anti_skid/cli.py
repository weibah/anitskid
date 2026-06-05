# cli to generate manifest.json
# usage: anti-skid-gen [folder]

import argparse
import os
import sys

from anti_skid.manifest import generate_manifest


def generate_manifest_cli(argv=None):
    # anti-skid-gen entry point
    p = argparse.ArgumentParser(
        description="make ur manifest.json so anti-skid knows what files to watch",
        prog="anti-skid-gen",
    )
    p.add_argument("root", nargs="?", default=".", help="project folder (default: here)")
    p.add_argument("-o", "--output", default=None, help="where to save manifest.json")
    p.add_argument(
        "--extensions",
        nargs="+",
        default=[".py", ".pyw", ".pyc", ".pyd", ".so", ".dll"],
        help="file types to include",
    )
    p.add_argument(
        "--exclude-dirs",
        nargs="+",
        default=[
            "__pycache__", ".git", ".svn", ".hg", "node_modules",
            "venv", ".venv", "env", "build", "dist", ".tox", ".eggs",
        ],
        help="folders to skip",
    )

    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"bro that aint a folder: {root}", file=sys.stderr)
        sys.exit(1)

    generate_manifest(
        root_dir=root,
        output_path=args.output,
        extensions=tuple(args.extensions),
        exclude_dirs=tuple(args.exclude_dirs),
    )