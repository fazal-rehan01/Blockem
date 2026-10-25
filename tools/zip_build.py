#!/usr/bin/env python3
"""Zip the built Firefox extension directory into a distributable .zip/.xpi."""
import os
import sys
import zipfile


def main():
    if len(sys.argv) != 3:
        print("usage: zip_build.py <source_dir> <output_zip>", file=sys.stderr)
        sys.exit(2)
    src, dst = sys.argv[1], sys.argv[2]
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(src):
            for name in files:
                full = os.path.join(root, name)
                zf.write(full, os.path.relpath(full, src))
    print("wrote", dst)


if __name__ == "__main__":
    main()