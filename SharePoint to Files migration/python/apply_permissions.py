# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# ACL Recovery Script for SharePoint to Azure Files Migration
# Applies NTFS permissions from .sp-metadata.json sidecar files
#
# Author: Shekhar Sorot (shsorot@microsoft.com)
# Created: February 2026

"""
ACL Recovery Script

This script reads .sp-metadata.json files and applies NTFS ACLs to files
using icacls. Use this when:
- ACL application failed during migration
- Azure Files share wasn't mounted with Entra ID auth during migration
- You need to re-apply permissions after the fact

Prerequisites:
- Windows machine
- Azure File Share mounted with Entra ID Kerberos authentication
- .sp-metadata.json files present in the mounted share

Usage:
    python apply_permissions.py Z:\\
    python apply_permissions.py Z:\\ --dry-run
    python apply_permissions.py Z:\\ --verbose
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

METADATA_FILENAME = ".sp-metadata.json"


def apply_permissions_from_metadata(
    root_path: Path,
    dry_run: bool = False,
    verbose: bool = False,
) -> tuple[int, int, int]:
    """
    Walk through directories and apply permissions from .sp-metadata.json files.

    Returns: (files_processed, files_succeeded, files_failed)
    """
    files_processed = 0
    files_succeeded = 0
    files_failed = 0

    # Find all .sp-metadata.json files
    metadata_files = list(root_path.rglob(METADATA_FILENAME))
    print(f"Found {len(metadata_files)} metadata files")

    for metadata_file in metadata_files:
        folder_path = metadata_file.parent

        try:
            with open(metadata_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"  [ERROR] Failed to read {metadata_file}: {e}")
            continue

        files_data = data.get("files", {})

        for filename, file_meta in files_data.items():
            file_path = folder_path / filename

            if not file_path.exists():
                if verbose:
                    print(f"  [SKIP] File not found: {file_path}")
                continue

            permissions = file_meta.get("permissions", [])
            if not permissions:
                if verbose:
                    print(f"  [SKIP] No permissions for: {filename}")
                continue

            files_processed += 1
            success = True

            for perm in permissions:
                sid = perm.get("sid", "")
                ntfs_perm = perm.get("ntfs", "Read")
                principal = perm.get("principal", "Unknown")

                if not sid or not sid.startswith("S-1-12-1-"):
                    continue  # Skip invalid SIDs

                # Map NTFS permission names to icacls format
                perm_map = {
                    "FullControl": "F",
                    "Modify": "M",
                    "ReadAndExecute": "RX",
                    "Read": "R",
                    "Write": "W",
                }
                icacls_perm = perm_map.get(ntfs_perm, "R")

                if dry_run:
                    print(f"  [DRY-RUN] Would apply {ntfs_perm} for {principal}")
                    print(f"            icacls \"{file_path}\" /grant *{sid}:{icacls_perm}")
                else:
                    try:
                        result = subprocess.run(
                            ["icacls", str(file_path), "/grant", f"*{sid}:{icacls_perm}"],
                            capture_output=True,
                            text=True,
                        )
                        if result.returncode != 0:
                            if verbose:
                                print(f"  [WARN] icacls failed for {filename}: {result.stderr}")
                            success = False
                        elif verbose:
                            print(f"  [OK] Applied {ntfs_perm} to {filename} for {principal}")
                    except Exception as e:
                        if verbose:
                            print(f"  [ERROR] Failed to apply ACL to {filename}: {e}")
                        success = False

            if success:
                files_succeeded += 1
            else:
                files_failed += 1

    return files_processed, files_succeeded, files_failed


def apply_timestamps_from_metadata(
    root_path: Path,
    dry_run: bool = False,
    verbose: bool = False,
) -> tuple[int, int, int]:
    """
    Walk through directories and apply timestamps from .sp-metadata.json files.

    Returns: (files_processed, files_succeeded, files_failed)
    """
    import os
    from datetime import datetime

    files_processed = 0
    files_succeeded = 0
    files_failed = 0

    # Find all .sp-metadata.json files
    metadata_files = list(root_path.rglob(METADATA_FILENAME))
    print(f"Found {len(metadata_files)} metadata files for timestamp recovery")

    for metadata_file in metadata_files:
        folder_path = metadata_file.parent

        try:
            with open(metadata_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"  [ERROR] Failed to read {metadata_file}: {e}")
            continue

        files_data = data.get("files", {})

        for filename, file_meta in files_data.items():
            file_path = folder_path / filename

            if not file_path.exists():
                continue

            modified = file_meta.get("modified")
            if not modified:
                continue

            files_processed += 1

            try:
                # Parse ISO timestamp
                dt = datetime.fromisoformat(modified.replace("Z", "+00:00"))
                mtime = dt.timestamp()

                if dry_run:
                    print(f"  [DRY-RUN] Would set mtime={modified} for {filename}")
                else:
                    os.utime(file_path, (mtime, mtime))
                    if verbose:
                        print(f"  [OK] Set timestamp for {filename}")
                    files_succeeded += 1

            except Exception as e:
                if verbose:
                    print(f"  [ERROR] Failed to set timestamp for {filename}: {e}")
                files_failed += 1

    return files_processed, files_succeeded, files_failed


def main():
    parser = argparse.ArgumentParser(
        description="Apply NTFS ACLs from .sp-metadata.json files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Apply permissions to mounted Azure File Share
  python apply_permissions.py Z:\\

  # Dry run - show what would be applied
  python apply_permissions.py Z:\\ --dry-run

  # Apply with verbose output
  python apply_permissions.py Z:\\ --verbose

  # Apply only timestamps
  python apply_permissions.py Z:\\ --timestamps-only

Requirements:
  - Azure File Share must be mounted with Entra ID Kerberos authentication
  - .sp-metadata.json files must be present (created during migration)
""",
    )

    parser.add_argument(
        "path",
        type=Path,
        help="Root path to apply permissions (e.g., Z:\\ for mounted share)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be applied without making changes",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed output for each file",
    )
    parser.add_argument(
        "--timestamps-only",
        action="store_true",
        help="Only apply timestamps, not ACLs",
    )
    parser.add_argument(
        "--acls-only",
        action="store_true",
        help="Only apply ACLs, not timestamps",
    )

    args = parser.parse_args()

    if not args.path.exists():
        print(f"Error: Path does not exist: {args.path}")
        sys.exit(1)

    print(f"Processing: {args.path}")
    if args.dry_run:
        print("[DRY-RUN MODE - no changes will be made]\n")

    total_processed = 0
    total_succeeded = 0
    total_failed = 0

    # Apply timestamps
    if not args.acls_only:
        print("\n=== Applying Timestamps ===")
        processed, succeeded, failed = apply_timestamps_from_metadata(
            args.path, args.dry_run, args.verbose
        )
        total_processed += processed
        total_succeeded += succeeded
        total_failed += failed
        print(f"Timestamps: {succeeded}/{processed} succeeded, {failed} failed")

    # Apply ACLs
    if not args.timestamps_only:
        print("\n=== Applying ACLs ===")
        processed, succeeded, failed = apply_permissions_from_metadata(
            args.path, args.dry_run, args.verbose
        )
        total_processed += processed
        total_succeeded += succeeded
        total_failed += failed
        print(f"ACLs: {succeeded}/{processed} succeeded, {failed} failed")

    # Summary
    print("\n" + "=" * 50)
    print(f"Total files processed: {total_processed}")
    print(f"Total succeeded: {total_succeeded}")
    print(f"Total failed: {total_failed}")

    sys.exit(0 if total_failed == 0 else 1)


if __name__ == "__main__":
    main()
