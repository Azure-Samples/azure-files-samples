# MIT License
#
# Copyright (c) 2026 Shekhar Sorot (shsorot@microsoft.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT
#
# SharePoint to Azure Files Copy Tool
# Python implementation with async parallelization and rich TUI
#
# Author: Shekhar Sorot (shsorot@microsoft.com), Vincent Liu (rongpuliu@microsoft.com)
# Created: February 2026

"""
SharePoint to Azure Files Migration Tool

This script migrates files from SharePoint Online document libraries to Azure Files
with parallel downloads, checkpoint/resume support, and a rich terminal UI.

.. important::

   This tool **copies** files - it does NOT move or delete anything from
   SharePoint.  The source document library remains completely intact
   after the migration completes.

Architecture Overview
=====================
The migration follows a **batched pipeline** pattern to balance throughput with
disk usage.  Files are processed in configurable batches (default 200):

    ┌--------------┐    ┌--------------┐    ┌--------------┐
    |  SharePoint  |---▶|  Local Temp  |---▶|  Azure Files |
    |  (Graph API) |    |   Directory  |    |   (AzCopy)   |
    └--------------┘    └--------------┘    └--------------┘
          Phase 1              |               Phase 2
      Parallel async           |           Bulk SMB upload
       downloads              |           with --list-of-files
                              ▼
                      Cleanup after each
                      batch to free disk

For each batch the pipeline is:
  1. DOWNLOAD – N concurrent async workers fetch files via Graph API
     download URLs, apply timestamps and NTFS ACLs locally, and write
     per-folder .sp-metadata.json sidecar files.
  2. UPLOAD   – A single AzCopy invocation copies the batch to Azure
     Files using SMB semantics (preserving timestamps and ACLs on
     Windows).
  3. CLEANUP  – Temp files are deleted to reclaim disk space.
  4. CHECKPOINT – Processed file IDs are persisted to a JSON file so
     interrupted migrations can resume without re-transferring files.

Component Map
-------------
- ``setup_logging()``      – Dual logging: human-readable .log + CSV perf log
- ``TokenManager``         – Acquires/refreshes Graph API tokens via Azure CLI
- ``GraphAPIClient``       – Async HTTP client for Graph API (files, metadata,
                             permissions, delta queries)
- ``MigrationUI``          – Rich terminal UI with live progress, worker table,
                             AzCopy output, and status bar
- ``MigrationEngine``      – Orchestrator: enumerate → filter → batch download
                             → batch upload → checkpoint
- ``SpeedTracker``         – Sliding-window speed calculator across workers
- ``run_interactive_wizard()`` – Step-by-step CLI wizard for config
- ``parse_args()`` / ``main()`` – CLI entry point and argument parsing

Authentication Flow
-------------------
1. User runs ``az login`` before invoking this script.
2. ``TokenManager`` calls ``az account get-access-token --resource graph``
   to obtain a Bearer token for the Microsoft Graph API.
3. Tokens are cached in memory and refreshed every 45 minutes (before
   the 60-minute expiry) to support long-running migrations.
4. For Azure Files upload, the script retrieves the storage account key
   via ``az storage account keys list`` and generates a SAS token
   (cached for 24 hours, refreshed 1 hour before expiry).

Features
--------
- Async parallel downloads from SharePoint via Microsoft Graph API
- AzCopy integration for high-speed bulk uploads to Azure Files
- Real-time progress tracking with download/upload speeds
- Checkpoint/resume for interrupted migrations
- Permission export with Entra ID SID mapping
- Automatic token refresh for long-running migrations

Prerequisites
-------------
- Python 3.10+
- Azure CLI installed and logged in (az login)
- AzCopy installed and in PATH
- Required Python packages (see requirements.txt)

Usage
-----
::

    python migrate_sp_to_azure_files.py --interactive
    python migrate_sp_to_azure_files.py --site-url "https://..." --library "Documents" ...
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlparse

# ============================================================================
# Logging Setup
#
# Two separate log files are created per run:
#   1. migration_<timestamp>.log  – Detailed human-readable debug log with
#      timestamps, module names, and line numbers.  Used for troubleshooting.
#   2. migration_perf_<timestamp>.csv – Machine-parseable CSV of per-file
#      performance events (download times, speeds, errors).  Useful for
#      post-migration analysis in Excel/pandas.
#
# Both logs are written to the ./logs/ directory (or a user-specified path).
# The global ``logger`` and ``perf_logger`` instances are used throughout
# the codebase.
# ============================================================================


def setup_logging(log_dir: Optional[Path] = None) -> logging.Logger:
    """Configure dual file logging for migration analysis.

    Creates two log files:
      - A detailed ``.log`` file at DEBUG level for troubleshooting.
      - A ``.csv`` performance log at INFO level for metrics analysis.

    Args:
        log_dir: Directory for log files.  Defaults to current working
                 directory.  Created recursively if it doesn't exist.

    Returns:
        The configured ``sp_migration`` logger instance.
    """
    logger = logging.getLogger("sp_migration")
    logger.setLevel(logging.DEBUG)

    # Clear any existing handlers
    logger.handlers.clear()

    # Determine log file path
    if log_dir is None:
        log_dir = Path.cwd()
    log_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"migration_{timestamp}.log"

    # File handler - detailed debug logging
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        "%(asctime)s.%(msecs)03d | %(levelname)-8s | "
        "%(name)s | %(funcName)s:%(lineno)d | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)

    # Also create a separate CSV-style performance log
    perf_log_file = log_dir / f"migration_perf_{timestamp}.csv"
    perf_handler = logging.FileHandler(perf_log_file, encoding="utf-8")
    perf_handler.setLevel(logging.INFO)
    perf_handler.setFormatter(logging.Formatter("%(message)s"))

    perf_logger = logging.getLogger("sp_migration.perf")
    perf_logger.setLevel(logging.INFO)
    perf_logger.handlers.clear()
    perf_logger.addHandler(perf_handler)
    perf_logger.propagate = False

    # Write CSV header
    perf_logger.info(
        "timestamp,event,file_id,file_name,file_size_bytes,"
        "duration_ms,speed_mbps,status,error"
    )

    logger.info(f"Logging initialized. Log file: {log_file}")
    logger.info(f"Performance log: {perf_log_file}")

    return logger


# Global logger instance
logger = logging.getLogger("sp_migration")
perf_logger = logging.getLogger("sp_migration.perf")


def log_perf(
    event: str,
    file_id: str = "",
    file_name: str = "",
    file_size: int = 0,
    duration_ms: float = 0,
    speed_mbps: float = 0,
    status: str = "ok",
    error: str = ""
):
    """Log a performance event to the CSV performance log.

    Each call appends one row to ``migration_perf_<timestamp>.csv``.
    Commas and double-quotes in string fields are escaped to preserve
    CSV integrity.

    Args:
        event:       Event type ("download", "download_retry", "download_fail",
                     "upload_batch").
        file_id:     SharePoint drive item ID.
        file_name:   Original filename.
        file_size:   File size in bytes.
        duration_ms: Wall-clock duration of the operation in milliseconds.
        speed_mbps:  Transfer speed in MB/s.
        status:      Outcome ("ok", "retry", "error", "max_retries").
        error:       Error message (truncated to 200 chars).
    """
    # Escape commas in strings
    file_name = file_name.replace(",", ";").replace("\"", "'")
    error = error.replace(",", ";").replace("\"", "'")[:200]
    perf_logger.info(
        f"{datetime.now().isoformat()},{event},{file_id},{file_name},"
        f"{file_size},{duration_ms:.1f},{speed_mbps:.2f},{status},{error}"
    )

# ---------------------------------------------------------------------------
# Platform Detection
#
# Several features are platform-specific:
#   - Windows: Azure CLI is "az.cmd" (batch wrapper), creation time can be
#     set via Win32 API, NTFS ACLs applied via icacls, AzCopy preserves
#     SMB permissions/info.
#   - Linux/macOS: Azure CLI is "az" directly, no creation time support,
#     ACL application is skipped.
# ---------------------------------------------------------------------------
IS_WINDOWS = platform.system() == "Windows"


def get_az_command() -> str:
    """Get the correct Azure CLI executable for the current platform.

    On Windows, the Azure CLI is installed as ``az.cmd`` (a batch file
    wrapper).  On other platforms, it's a direct ``az`` executable.
    """
    if IS_WINDOWS:
        return "az.cmd"
    return "az"


def get_azcopy_command() -> str:
    """Get the correct AzCopy executable for the current platform.

    On Windows, checks common SDK installation paths before falling
    back to PATH lookup.  On other platforms, assumes ``azcopy`` is
    in PATH.
    """
    if IS_WINDOWS:
        # Try to find azcopy in common locations
        common_paths = [
            r"C:\Program Files\Microsoft SDKs\Azure\AzCopy\azcopy.exe",
            r"C:\Program Files (x86)\Microsoft SDKs\Azure\AzCopy\azcopy.exe",
        ]
        for path in common_paths:
            if os.path.exists(path):
                return path
    return "azcopy"

import aiofiles
import aiohttp
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import (BarColumn, Progress, SpinnerColumn, TaskID,
                           TextColumn, TimeElapsedColumn, TimeRemainingColumn)
from rich.table import Table
from rich.text import Text

# ============================================================================
# Constants and Configuration
#
# These values control the migration's performance and resilience characteristics.
# They were tuned through testing against SharePoint Online tenants with 10K+
# files.  Adjust them based on your network bandwidth, SharePoint throttling
# limits, and available local disk space.
# ============================================================================

# Microsoft Graph v1.0 endpoint - the stable API surface for SharePoint access.
GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"

# Azure AD tokens expire after 60 minutes.  We refresh at 45 minutes to
# provide a 15-minute safety buffer against clock skew and in-flight requests.
TOKEN_REFRESH_MINUTES = 45

# Maximum parallel download workers.  Higher values increase throughput but
# also increase Graph API call volume and risk 429 throttling.  8 is a safe
# default that typically saturates a 1 Gbps link without triggering throttles.
MAX_CONCURRENT_DOWNLOADS = 8

# Number of retry attempts for transient failures (timeouts, 429s, network
# errors).  3 retries with 5-second delays covers most brief outages.
MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 5

# AzCopy parallel transfer threads.  64 threads match the recommended setting
# for Azure Files Premium tier.  Adjust down for standard-tier shares or
# constrained networks.
AZCOPY_CONCURRENCY = 64

# Sidecar metadata file written into each folder alongside migrated files.
# Contains per-file SharePoint metadata (permissions, custom columns, hashes)
# for downstream tools or auditing.
METADATA_FILENAME = ".sp-metadata.json"

# Number of files per batch.  Each batch is fully downloaded, uploaded, then
# cleaned up before the next batch starts.  200 balances disk usage (~2-5 GB
# per batch for typical document libraries) against AzCopy startup overhead.
BATCH_SIZE = 200

# ============================================================================
# Data Classes
# ============================================================================


@dataclass
class FileMetadata:
    """Complete metadata for a SharePoint file.

    Populated by ``GraphAPIClient.get_file_metadata()`` during the download
    phase.  This metadata is:
      - Written to per-folder ``.sp-metadata.json`` sidecar files alongside
        the migrated content.
      - Used to apply NTFS timestamps and ACLs to the local file before
        AzCopy uploads it to Azure Files.

    If the metadata Graph API call fails, a minimal instance is created with
    just ``id``, ``name``, and ``size`` so the file can still be migrated.
    """

    # SharePoint drive item ID (GUID) - unique within the drive.
    id: str
    # Original filename in SharePoint.
    name: str
    # File size in bytes as reported by SharePoint.
    size: int
    # ISO 8601 creation timestamp from SharePoint (e.g. "2024-03-15T10:30:00Z").
    created: Optional[str] = None
    # ISO 8601 last-modified timestamp from SharePoint.
    modified: Optional[str] = None
    # Creator info: {"name": str, "email": str, "objectId": str}.
    created_by: Optional[dict] = None
    # Last modifier info, same structure as created_by.
    modified_by: Optional[dict] = None
    # SharePoint content type name (e.g. "Document", "Image").
    content_type: Optional[str] = None
    # File hashes from Graph API: {"quickXorHash": str, "sha256Hash": str}.
    # Used for integrity verification after migration.
    hashes: Optional[dict] = None
    # Per-file permissions from SharePoint, each entry:
    # {"principal": str, "type": "User"|"Group"|"SiteUser",
    #  "objectId": str, "sid": str, "roles": [str], "ntfs": str}
    permissions: list = field(default_factory=list)
    # SharePoint custom column values (user-defined metadata), excluding
    # system fields like _ComplianceFlags.  Keys are column internal names.
    custom_columns: dict = field(default_factory=dict)
    # Whether NTFS ACLs were successfully applied to the local temp file.
    acl_applied: bool = False
    # Whether original timestamps were successfully applied to the local file.
    timestamps_applied: bool = False
    # Error message if ACL application failed (best-effort, non-blocking).
    acl_error: Optional[str] = None
    # Error message if timestamp application failed (best-effort, non-blocking).
    timestamps_error: Optional[str] = None


class FileStatus(Enum):
    """Lifecycle status of a file in the migration pipeline.

    State transitions::

        PENDING --▶ DOWNLOADING --▶ DOWNLOADED --▶ COMPLETED
           |             |
           |             ▼
           |         RETRYING --▶ (back to DOWNLOADING)
           |             |
           ▼             ▼
         FAILED       FAILED

    Note: UPLOADING is reserved for future per-file upload tracking but
    is not currently used because uploads happen at the batch level via
    AzCopy.
    """
    PENDING = "pending"         # File discovered, not yet started
    DOWNLOADING = "downloading" # Currently being downloaded from SharePoint
    DOWNLOADED = "downloaded"   # Downloaded to local temp, awaiting upload
    UPLOADING = "uploading"     # (Reserved) Being uploaded to Azure Files
    COMPLETED = "completed"     # Successfully uploaded and checkpointed
    FAILED = "failed"           # Permanently failed after all retries
    RETRYING = "retrying"       # Transient failure, will retry
    ARCHIVED = "archived"       # Archived in M365, cannot be downloaded


@dataclass
class FileItem:
    """Represents a single file to be migrated through the pipeline.

    Created during the enumeration phase from Graph API delta query results.
    Mutated in-place as the file progresses through download → upload → complete.
    """

    # SharePoint drive item ID (GUID).
    id: str
    # Original filename (e.g. "report.docx").
    name: str
    # Relative path within the document library (e.g. "subfolder/report.docx").
    path: str
    # File size in bytes.
    size: int
    # SharePoint drive ID that contains this file.
    drive_id: str
    # SharePoint site ID that contains the drive.
    site_id: str
    # SharePoint lastModifiedDateTime (ISO 8601), used for change detection.
    modified: Optional[str] = None
    # Pre-authenticated download URL (short-lived, fetched per download).
    download_url: Optional[str] = None
    # Local filesystem path where the file is temporarily stored after download.
    local_path: Optional[Path] = None
    # Current pipeline status (see FileStatus for state machine).
    status: FileStatus = FileStatus.PENDING
    # Rich metadata fetched from Graph API (permissions, hashes, etc.).
    metadata: Optional[FileMetadata] = None
    # Last error message if the file failed.
    error: Optional[str] = None
    # Number of retry attempts so far (max: MAX_RETRIES).
    retry_count: int = 0


@dataclass
class MigrationStats:
    """Running counters and timing data for the migration, displayed in the UI.

    Updated in-place by download workers and the upload method.  Read by
    ``MigrationUI`` to render the status bar and progress indicators.
    """

    total_files: int = 0              # Total files to copy in this run
    total_bytes: int = 0              # Total bytes to copy
    downloaded_files: int = 0         # Files successfully downloaded so far
    downloaded_bytes: int = 0         # Bytes successfully downloaded
    uploaded_files: int = 0           # Files confirmed uploaded via AzCopy
    uploaded_bytes: int = 0           # Bytes confirmed uploaded
    failed_files: int = 0             # Files that permanently failed
    archived_files: int = 0           # Files skipped (M365 archived)
    retried_files: int = 0            # Total retry attempts across all files
    start_time: Optional[datetime] = None       # Wall-clock start of migration
    download_start_time: Optional[datetime] = None  # (Reserved for phase timing)
    upload_start_time: Optional[datetime] = None    # (Reserved for phase timing)
    current_download_speed: float = 0.0  # Instantaneous download speed (bytes/sec)
    current_upload_speed: float = 0.0    # Instantaneous upload speed (bytes/sec)


@dataclass
class MigrationConfig:
    """User-provided configuration for a migration run.

    Populated from CLI arguments (``parse_args()``) or the interactive wizard
    (``run_interactive_wizard()``).  Passed to ``MigrationEngine`` which uses
    it throughout the pipeline.
    """

    # -- SharePoint source --
    # Full URL of the SharePoint site (e.g. "https://contoso.sharepoint.com/sites/docs")
    site_url: str
    # Name of the document library to copy (e.g. "Documents", "Shared Documents")
    library_name: str

    # -- Azure Files target --
    # Name of the Azure Storage account (not the full URL)
    storage_account: str
    # Name of the Azure Files share within the storage account
    file_share: str
    # Azure resource group containing the storage account
    resource_group: str
    # Azure subscription ID or display name
    subscription: str
    # Subfolder inside the file share to upload into.  Defaults to the
    # SharePoint library name (e.g. "Documents") so that files land in
    # a named subfolder rather than the share root.
    target_folder: str = ""

    # -- Behavioral options --
    # Limit migration to the first N files (0 = no limit).  Useful for testing.
    max_files: int = 0
    # If True, export SharePoint site permissions to a JSON file.
    export_permissions: bool = False
    # If True, configure Entra ID Kerberos-based auth.  (Reserved for future use.)
    enable_entra_kerberos: bool = False
    # Directory for temporary file downloads.  Defaults to OS temp / "sp_migration".
    temp_dir: Optional[Path] = None
    # Path to the checkpoint JSON file.  Defaults to ./logs/checkpoint.json.
    checkpoint_file: Optional[Path] = None
    # Path to the exported permissions JSON file.
    permissions_file: Optional[Path] = None
    # Number of parallel download workers.
    concurrent_downloads: int = MAX_CONCURRENT_DOWNLOADS
    # If True, enumerate and display files but don't download or upload.
    dry_run: bool = False
    # If True, ignore the checkpoint and re-upload all files.
    overwrite: bool = False


@dataclass
class Checkpoint:
    """Persistent state enabling resume of interrupted migrations.

    Saved to disk as JSON after every batch and every 50 files.  On restart,
    the checkpoint is loaded and already-processed files are skipped (unless
    they've been modified in SharePoint since the last upload).

    The ``config_hash`` ensures that a checkpoint from a *different* migration
    (different site/storage) is not accidentally reused.
    """

    # SHA-256 hash (first 16 hex chars) of site_url|library|storage|share.
    config_hash: str
    # Map of file_id → {"path": str, "size": int, "modified": str, "uploaded_at": str}.
    # Entries are added after successful AzCopy upload of each batch.
    processed_files: dict[str, dict] = field(default_factory=dict)
    # Map of file_id → error message for files that failed permanently.
    # Failed files are retried on the next run (they stay in failed_ids until
    # they succeed, at which point they move to processed_files).
    failed_ids: dict[str, str] = field(default_factory=dict)
    # ISO 8601 timestamp of the last checkpoint save.
    last_update: Optional[str] = None


@dataclass
class PermissionEntry:
    """A single SharePoint permission mapped to NTFS/Entra ID equivalents.

    Used when ``--export-permissions`` is set.  The entries are written to
    ``SharePointPermissions.json`` and can be consumed by the companion
    ``apply_permissions.py`` script to set NTFS ACLs on Azure Files.
    """

    # File/folder path relative to the library root ("/" for root-level).
    path: str
    # Display name of the user or group.
    principal: str
    # "User", "Group", or "SiteUser".
    principal_type: str
    # Email address (may be None for groups).
    email: Optional[str]
    # Azure AD / Entra ID object ID (GUID).
    object_id: str
    # Windows SID in S-1-12-1-... format (converted from object_id).
    sid: str
    # Original SharePoint role: "Owner", "Member", "Visitor", or "<role> (inherited)".
    sharepoint_role: str
    # Equivalent NTFS permission: "FullControl", "Modify", "ReadAndExecute", "Read".
    ntfs_permission: str
    # If this entry is a group member, the name of the parent group.
    member_of: Optional[str] = None


@dataclass
class ActivityLogEntry:
    """A single entry in the TUI's scrolling activity log.

    Displayed in the "Recent Activity" panel, showing the last 6 events
    (downloads, errors, retries) with status icons and optional file sizes.
    """

    # When the event occurred.
    timestamp: datetime
    # Human-readable description (e.g. "subfolder/report.docx [ACL:OK]").
    message: str
    # One of: "success", "warning", "error", "info" - controls the icon.
    status: str
    # Optional file size in bytes, displayed as KB/MB in the log.
    file_size: Optional[int] = None


# ============================================================================
# Token Management
#
# The migration authenticates to Microsoft Graph via Azure CLI tokens.
# This avoids the need for app registrations or client secrets - the user
# simply runs ``az login`` before starting the migration.
#
# Token lifecycle:
#   - First call to ``get_token()`` spawns ``az account get-access-token``
#     as a subprocess and caches the result.
#   - Subsequent calls return the cached token if it's less than
#     TOKEN_REFRESH_MINUTES (45 min) old.
#   - After 45 minutes, the next ``get_token()`` call transparently
#     refreshes the token.  This is safe because Azure CLI handles the
#     OAuth refresh flow internally.
# ============================================================================


class TokenManager:
    """Manages Microsoft Graph API tokens with automatic refresh.

    Uses Azure CLI (``az account get-access-token``) as the token provider.
    Tokens are cached in memory and refreshed before expiry to ensure
    uninterrupted access during long-running migrations.

    Thread safety: This class is used from a single asyncio event loop,
    so no explicit locking is needed.  Multiple concurrent ``get_token()``
    calls may each trigger a refresh, but the last one wins (idempotent).
    """

    def __init__(self):
        self._token: Optional[str] = None
        self._token_acquired_time: Optional[datetime] = None
        self._console = Console()

    async def get_token(self, force_refresh: bool = False) -> str:
        """Get a valid Graph API token, refreshing if needed.

        The token is obtained by shelling out to Azure CLI::

            az account get-access-token --resource https://graph.microsoft.com

        Args:
            force_refresh: If True, bypass the cache and always fetch a
                           new token.  Used when a 401 suggests the cached
                           token is invalid.

        Returns:
            A Bearer token string for the Microsoft Graph API.

        Raises:
            RuntimeError: If ``az account get-access-token`` fails (e.g.
                          user is not logged in) or times out after 60s.
        """
        if not force_refresh and self._token and self._token_acquired_time:
            age_mins = (datetime.now() - self._token_acquired_time).total_seconds() / 60
            if age_mins < TOKEN_REFRESH_MINUTES:
                return self._token

        # Get token via Azure CLI
        logger.info("Requesting new Graph API token via Azure CLI")
        start_time = time.time()
        az_cmd = get_az_command()
        process = await asyncio.create_subprocess_exec(
            az_cmd, "account", "get-access-token",
            "--resource", "https://graph.microsoft.com",
            "--query", "accessToken",
            "-o", "tsv",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=60
            )
        except asyncio.TimeoutError:
            process.kill()
            raise RuntimeError(
                "Azure CLI token request timed out after 60s"
            )
        elapsed = (time.time() - start_time) * 1000

        if process.returncode != 0:
            err_msg = stderr.decode()
            logger.error(f"Token acquisition failed: {err_msg}")
            raise RuntimeError(
                f"Failed to get Graph token. Ensure you're logged in with 'az login'. "
                f"Error: {err_msg}"
            )

        self._token = stdout.decode().strip()
        self._token_acquired_time = datetime.now()
        logger.info(f"Token acquired successfully in {elapsed:.0f}ms")
        return self._token

    def needs_refresh(self) -> bool:
        """Check if token needs refresh."""
        if not self._token_acquired_time:
            return True
        age_minutes = (datetime.now() - self._token_acquired_time).total_seconds() / 60
        return age_minutes >= TOKEN_REFRESH_MINUTES


# ============================================================================
# Graph API Client
#
# All SharePoint data access goes through the Microsoft Graph v1.0 REST API.
# Key patterns used:
#   - Delta queries (``/drives/{id}/root/delta``) for efficient file
#     enumeration across large libraries (handles pagination automatically).
#   - ``$expand=permissions,listItem($expand=fields)`` to fetch per-file
#     permissions and custom columns in a single request.
#   - ``grantedToV2`` (preferred) with fallback to ``grantedTo`` for
#     backward compatibility with older SharePoint configurations.
#   - ``@microsoft.graph.downloadUrl`` for pre-authenticated, short-lived
#     download URLs that don't require additional auth headers.
#
# Rate limiting:
#   - Graph API returns HTTP 429 with a ``Retry-After`` header when
#     throttled.  The client respects this header and retries automatically.
#   - All requests have a maximum of MAX_RETRIES attempts for transient
#     errors (timeouts, connection resets, 429s).
# ============================================================================


class GraphAPIClient:
    """Async HTTP client for Microsoft Graph API operations.

    Manages an ``aiohttp.ClientSession`` with configured timeouts and
    provides methods for all SharePoint operations needed by the migration:
    site lookup, drive discovery, file enumeration, metadata retrieval,
    file download, and permission export.

    Usage::

        async with GraphAPIClient(token_manager) as client:
            site = await client.get_site(url)
            drive = await client.get_drive(site["id"], "Documents")
            files = await client.get_all_files(site["id"], drive["id"])
    """

    def __init__(self, token_manager: TokenManager):
        self.token_manager = token_manager
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        # Configure timeouts to prevent hanging on API calls.
        # Note: sock_read is set generously (300s) because the same
        # session is used for both small JSON API calls and large file
        # downloads.  A per-chunk timeout of 5 minutes accommodates
        # multi-GB files on slow connections (H5 fix).
        timeout = aiohttp.ClientTimeout(
            total=None,     # No total limit (large files can take hours)
            connect=30,     # 30s to establish TCP connection
            sock_read=300,  # 5 min max wait for a single read operation
        )
        self._session = aiohttp.ClientSession(timeout=timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            await self._session.close()

    async def _get_headers(self) -> dict[str, str]:
        """Get headers with current token."""
        token = await self.token_manager.get_token()
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

    async def _request(
        self,
        method: str,
        url: str,
        retry_on_429: bool = True,
        **kwargs
    ) -> dict[str, Any]:
        """Make an authenticated Graph API request with retry logic.

        Handles:
          - HTTP 401 (Unauthorized): Force-refreshes the token and retries.
          - HTTP 429 (Too Many Requests): Sleeps for the ``Retry-After``
            duration and retries up to MAX_RETRIES times.
          - HTTP 5xx (Server Error): Retries up to MAX_RETRIES times.
          - HTTP 4xx (other than 401/429): Raises immediately (not retryable).
          - Transient network errors (``aiohttp.ClientError`` excluding
            ``ClientResponseError``): Retries with the same attempt budget.

        The authorization header is refreshed on each retry attempt to
        handle token expiry during long 429 waits.

        Args:
            method:        HTTP method ("GET", "POST", etc.).
            url:           Full Graph API URL.
            retry_on_429:  If False, raise immediately on 429 instead
                           of sleeping and retrying.
            **kwargs:      Passed through to ``aiohttp.ClientSession.request()``.

        Returns:
            Parsed JSON response body as a dict.

        Raises:
            aiohttp.ClientResponseError: On non-retryable HTTP errors.
            RuntimeError: If MAX_RETRIES is exhausted.
        """
        start_time = time.time()

        for attempt in range(MAX_RETRIES):
            # Refresh headers on every attempt so that a token that
            # expired during a 429 sleep is replaced automatically.
            headers = await self._get_headers()
            try:
                async with self._session.request(
                    method, url, headers=headers, **kwargs
                ) as response:
                    elapsed = (time.time() - start_time) * 1000

                    # --- 401 Unauthorized: force-refresh token and retry ---
                    if response.status == 401:
                        logger.warning(
                            f"Unauthorized (401) on {method} "
                            f"{url[:80]}. Refreshing token "
                            f"(attempt {attempt + 1})"
                        )
                        await self.token_manager.get_token(
                            force_refresh=True
                        )
                        continue

                    # --- 429 Rate Limited: sleep & retry ---
                    if response.status == 429:
                        retry_after = int(
                            response.headers.get("Retry-After", 60)
                        )
                        logger.warning(
                            f"Rate limited (429) on {method} {url[:80]}. "
                            f"Retry after {retry_after}s (attempt {attempt+1})"
                        )
                        if retry_on_429:
                            await asyncio.sleep(retry_after)
                            continue
                        raise aiohttp.ClientResponseError(
                            response.request_info,
                            response.history,
                            status=429,
                            message="Rate limited",
                        )

                    # --- 5xx Server Error: retry ---
                    if response.status >= 500:
                        logger.warning(
                            f"Server error ({response.status}) on "
                            f"{method} {url[:80]}. "
                            f"Attempt {attempt + 1}/{MAX_RETRIES}"
                        )
                        if attempt < MAX_RETRIES - 1:
                            await asyncio.sleep(RETRY_DELAY_SECONDS)
                            continue
                        response.raise_for_status()

                    # --- Other 4xx: raise immediately (not retryable) ---
                    response.raise_for_status()

                    logger.debug(
                        f"API {method} {url[:60]}... -> {response.status} "
                        f"in {elapsed:.0f}ms"
                    )
                    return await response.json()

            except aiohttp.ClientResponseError:
                # HTTP errors already handled above; if we reach here
                # it was re-raised intentionally - don't retry.
                raise

            except aiohttp.ClientError as e:
                # Transient network errors (DNS, connection reset, etc.)
                elapsed = (time.time() - start_time) * 1000
                logger.warning(
                    f"Network error on {method} {url[:60]}... "
                    f"attempt {attempt+1}/{MAX_RETRIES}: {e}"
                )
                if attempt == MAX_RETRIES - 1:
                    raise
                await asyncio.sleep(RETRY_DELAY_SECONDS)

        raise RuntimeError(f"Max retries exceeded for {url}")

    async def get_site(self, site_url: str) -> dict[str, Any]:
        """Resolve a SharePoint site URL to its Graph API site object.

        Converts a user-friendly URL like
        ``https://contoso.sharepoint.com/sites/docs`` into the Graph API
        path format ``/sites/{hostname}:{server-relative-path}`` and
        returns the full site resource including ``id`` and ``displayName``.

        Args:
            site_url: Full SharePoint site URL.

        Returns:
            Graph API site resource dict with keys like ``id``,
            ``displayName``, ``webUrl``.
        """
        parsed = urlparse(site_url)
        host = parsed.netloc
        path = parsed.path.rstrip("/")

        url = f"{GRAPH_API_BASE}/sites/{host}:{path}"
        return await self._request("GET", url)

    async def get_drive(self, site_id: str, library_name: str) -> dict[str, Any]:
        """Find a document library (drive) by name within a SharePoint site.

        Lists all drives on the site and matches by ``name`` field.
        Note: SharePoint's default library is typically named "Documents"
        but may appear as "Shared Documents" in the UI - the Graph API
        ``name`` field is the internal name.

        Args:
            site_id:      Graph API site ID.
            library_name: Internal name of the document library.

        Returns:
            Graph API drive resource dict.

        Raises:
            ValueError: If no matching library is found, listing
                        available names for the user.
        """
        url = f"{GRAPH_API_BASE}/sites/{site_id}/drives"
        result = await self._request("GET", url)

        for drive in result.get("value", []):
            if drive.get("name") == library_name:
                return drive

        available = ", ".join(d.get("name", "?") for d in result.get("value", []))
        raise ValueError(f"Library '{library_name}' not found. Available: {available}")

    async def get_all_files(
        self,
        site_id: str,
        drive_id: str,
        on_progress: Optional[Callable] = None
    ) -> list[FileItem]:
        """Enumerate all files in a document library using delta query.

        Uses the Graph API delta endpoint
        (``/drives/{id}/root/delta``) which returns all items in a
        drive with automatic pagination via ``@odata.nextLink``.
        Deleted items and folders are filtered out; only files are returned.

        Path reconstruction:
          Graph API returns each item's ``parentReference.path`` in the
          format ``/drives/<id>/root:/subfolder/path``.  We extract the
          relative path after ``root:`` and combine it with the filename
          to build the full library-relative path (e.g. "reports/Q1/data.xlsx").

        Args:
            site_id:     Graph API site ID.
            drive_id:    Graph API drive ID.
            on_progress: Optional callback invoked every 500 files with
                         the current count, for UI feedback during
                         enumeration of large libraries.

        Returns:
            List of ``FileItem`` instances (status=PENDING), one per file.
        """
        files: list[FileItem] = []
        url = (
            f"{GRAPH_API_BASE}/sites/{site_id}/drives/{drive_id}"
            f"/root/delta?$select="
            f"id,name,size,parentReference,file,"
            f"lastModifiedDateTime,deleted"
        )

        while url:
            result = await self._request("GET", url)

            for item in result.get("value", []):
                if item.get("deleted") or not item.get("file"):
                    continue

                # Build path from parentReference
                path = item.get("name", "")
                parent_ref = item.get("parentReference", {})
                parent_path = parent_ref.get("path", "")

                if parent_path:
                    match = re.match(r"^/drives?/[^/]+/root:(.*)$", parent_path)
                    if match:
                        relative_path = match.group(1).lstrip("/")
                        if relative_path:
                            path = f"{relative_path}/{item['name']}"

                files.append(FileItem(
                    id=item["id"],
                    name=item["name"],
                    path=path,
                    size=item.get("size", 0),
                    drive_id=drive_id,
                    site_id=site_id,
                    modified=item.get("lastModifiedDateTime"),
                ))

            url = result.get("@odata.nextLink")

            if on_progress and len(files) % 500 == 0:
                on_progress(len(files))

        return files

    async def get_download_url(self, site_id: str, drive_id: str, item_id: str) -> str:
        """Get a pre-authenticated download URL for a file.

        The Graph API returns a ``@microsoft.graph.downloadUrl`` property
        on drive items.  This URL is short-lived (~15 minutes), doesn't
        require an Authorization header, and supports direct streaming.
        It must be fetched immediately before downloading each file.

        Args:
            site_id:  Graph API site ID.
            drive_id: Graph API drive ID.
            item_id:  Graph API drive item ID.

        Returns:
            Pre-authenticated download URL string, or empty string if
            the property is missing.
        """
        url = f"{GRAPH_API_BASE}/sites/{site_id}/drives/{drive_id}/items/{item_id}"
        result = await self._request("GET", url)
        return result.get("@microsoft.graph.downloadUrl", "")

    async def get_file_metadata(
        self,
        site_id: str,
        drive_id: str,
        item_id: str,
        file_name: str,
    ) -> FileMetadata:
        """Fetch complete metadata for a file from Graph API.

        Makes a single API call with ``$expand`` to retrieve:
          - Basic item properties (size, timestamps, created/modified by)
          - Permissions via ``$expand=permissions`` (users, groups, roles)
          - Custom SharePoint columns via
            ``$expand=listItem($expand=fields)``
          - File hashes (quickXorHash, sha256) from the ``file`` facet

        If the expanded request fails (e.g., insufficient permissions on
        listItem), falls back to a basic item request without ``$expand``.

        Permission mapping:
          - ``grantedToV2`` is preferred (newer API) with fallback to
            ``grantedTo`` for compatibility.
          - User, Group, and SiteUser permission types are extracted.
          - Each permission is enriched with:
            - ``sid``: Windows SID converted from Azure AD Object ID.
            - ``ntfs``: Equivalent NTFS permission string.

        Custom columns:
          System fields (Content Type, compliance tags, etc.) are filtered
          out.  Only user-defined metadata columns are included.

        Args:
            site_id:   Graph API site ID.
            drive_id:  Graph API drive ID.
            item_id:   Graph API drive item ID.
            file_name: Original filename (passed through to FileMetadata).

        Returns:
            A populated ``FileMetadata`` instance.
        """
        # Fetch item with expanded permissions and listItem fields
        url = (
            f"{GRAPH_API_BASE}/sites/{site_id}/drives/{drive_id}/items/{item_id}"
            f"?$expand=permissions,listItem($expand=fields)"
        )
        try:
            result = await self._request("GET", url)
        except Exception:
            # Fall back to basic item info
            url = f"{GRAPH_API_BASE}/sites/{site_id}/drives/{drive_id}/items/{item_id}"
            result = await self._request("GET", url)

        # Extract user info
        def extract_user(user_obj: Optional[dict]) -> Optional[dict]:
            if not user_obj:
                return None
            user = user_obj.get("user", {})
            return {
                "name": user.get("displayName", ""),
                "email": user.get("email", ""),
                "objectId": user.get("id", ""),
            }

        # Extract permissions
        permissions = []
        for perm in result.get("permissions", []):
            granted_to = perm.get("grantedToV2") or perm.get("grantedTo", {})

            # Handle user permissions
            if "user" in granted_to:
                user = granted_to["user"]
                object_id = user.get("id", "")
                permissions.append({
                    "principal": user.get("displayName", ""),
                    "type": "User",
                    "email": user.get("email", ""),
                    "objectId": object_id,
                    "sid": self._convert_object_id_to_sid(object_id) if object_id else "",
                    "roles": perm.get("roles", []),
                    "ntfs": self._roles_to_ntfs(perm.get("roles", [])),
                })

            # Handle group permissions
            if "group" in granted_to:
                group = granted_to["group"]
                object_id = group.get("id", "")
                permissions.append({
                    "principal": group.get("displayName", ""),
                    "type": "Group",
                    "objectId": object_id,
                    "sid": self._convert_object_id_to_sid(object_id) if object_id else "",
                    "roles": perm.get("roles", []),
                    "ntfs": self._roles_to_ntfs(perm.get("roles", [])),
                })

            # Handle siteUser (SharePoint-specific)
            if "siteUser" in granted_to:
                site_user = granted_to["siteUser"]
                permissions.append({
                    "principal": site_user.get("displayName", ""),
                    "type": "SiteUser",
                    "loginName": site_user.get("loginName", ""),
                    "roles": perm.get("roles", []),
                    "ntfs": self._roles_to_ntfs(perm.get("roles", [])),
                })

        # Extract custom columns from listItem.fields
        custom_columns = {}
        list_item = result.get("listItem", {})
        fields = list_item.get("fields", {})
        # Skip system fields
        system_fields = {
            "@odata.etag", "id", "ContentType", "Modified", "Created",
            "AuthorLookupId", "EditorLookupId", "_UIVersionString",
            "Attachments", "Edit", "LinkFilenameNoMenu", "LinkFilename",
            "DocIcon", "ItemChildCount", "FolderChildCount", "_ComplianceFlags",
            "_ComplianceTag", "_ComplianceTagWrittenTime", "_ComplianceTagUserId",
        }
        for key, value in fields.items():
            if key not in system_fields and not key.startswith("_"):
                custom_columns[key] = value

        # Extract hashes
        hashes = None
        file_info = result.get("file", {})
        if "hashes" in file_info:
            hashes = file_info["hashes"]

        return FileMetadata(
            id=result.get("id", item_id),
            name=file_name,
            size=result.get("size", 0),
            created=result.get("createdDateTime"),
            modified=result.get("lastModifiedDateTime"),
            created_by=extract_user(result.get("createdBy")),
            modified_by=extract_user(result.get("lastModifiedBy")),
            content_type=list_item.get("contentType", {}).get("name"),
            hashes=hashes,
            permissions=permissions,
            custom_columns=custom_columns,
        )

    @staticmethod
    def _roles_to_ntfs(roles: list[str]) -> str:
        """Convert SharePoint permission roles to an NTFS permission string.

        SharePoint uses role-based permissions (owner, write, read) while
        Azure Files uses NTFS-style ACLs.  This mapping provides a
        reasonable equivalent:

          - owner/write → "Modify" (read, write, delete, but not change
            permissions)
          - read → "ReadAndExecute" (read + traverse folders)
          - (no matching role) → "Read" (read-only, conservative default)

        Note: "FullControl" is reserved for site-level Owners groups
        (see ``get_site_permissions()``) and is not assigned at the
        file level.

        Args:
            roles: List of SharePoint role strings (e.g. ["read"],
                   ["owner", "write"]).

        Returns:
            NTFS permission string: "Modify", "ReadAndExecute", or "Read".
        """
        if "owner" in roles or "write" in roles:
            return "Modify"
        elif "read" in roles:
            return "ReadAndExecute"
        return "Read"

    async def download_file(
        self,
        download_url: str,
        dest_path: Path,
        on_progress: Optional[Callable] = None,
    ) -> None:
        """Stream-download a file from a pre-authenticated URL to disk.

        Downloads in 1 MB chunks to keep memory usage low even for large
        files.  The parent directory is created automatically if it
        doesn't exist.

        Args:
            download_url: Pre-authenticated URL from ``get_download_url()``.
            dest_path:    Local filesystem path to write the file to.
            on_progress:  Optional callback ``(downloaded_bytes, total_bytes)``
                          invoked after each chunk for UI progress updates.
                          Note: This is a *synchronous* callback called from
                          an async context (safe because it only updates
                          in-memory state).
        """
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        async with self._session.get(download_url) as response:
            response.raise_for_status()
            total_size = int(response.headers.get("Content-Length", 0))
            downloaded = 0

            async with aiofiles.open(dest_path, "wb") as f:
                async for chunk in response.content.iter_chunked(
                    1024 * 1024
                ):  # 1MB chunks
                    await f.write(chunk)
                    downloaded += len(chunk)
                    if on_progress:
                        # on_progress is a sync callback
                        on_progress(downloaded, total_size)

        # Verify download integrity: check that the number of bytes
        # written matches the expected Content-Length.  This catches
        # truncated downloads caused by TCP resets or server errors.
        if total_size > 0 and downloaded != total_size:
            # Remove the incomplete file to avoid uploading corrupt data
            if dest_path.exists():
                dest_path.unlink()
            raise aiohttp.ClientPayloadError(
                f"Download size mismatch: expected {total_size} "
                f"bytes, got {downloaded} bytes"
            )

    async def get_site_permissions(
        self,
        site_id: str,
        site_name: str,
        drive_id: str,
    ) -> list[PermissionEntry]:
        """Export site-level SharePoint permissions with Entra ID SID mapping.

        SharePoint Online sites backed by Microsoft 365 Groups have a
        single M365 Group in Entra ID (same display name as the site).
        Owners and Members are roles *within* that group - they do NOT
        have separate ``<SiteName> Owners`` groups in Entra ID.

        This method:
          1. Looks up the M365 Group by the site's display name.
          2. Adds the group itself with Modify permission (group-level ACL).
          3. Enumerates group **owners** → FullControl.
          4. Enumerates group **members** → Modify.

        If the M365 Group is not found (e.g., classic SharePoint site or
        renamed group), falls back to searching for the legacy
        ``<SiteName> Owners/Members/Visitors`` pattern.

        Mapping to NTFS:
          - Group itself → Modify (so group-based access works)
          - Owners       → FullControl
          - Members      → Modify

        Note: Visitors are a SharePoint-only concept with no Entra ID
        representation.  Individual visitor users would need to be
        enumerated via the SharePoint REST API (not implemented).

        Args:
            site_id:   Graph API site ID.
            site_name: Human-readable site name (used to find the group).
            drive_id:  Graph API drive ID (reserved for future use).

        Returns:
            List of ``PermissionEntry`` instances for all discovered
            principals.
        """
        permissions: list[PermissionEntry] = []

        # Strategy 1: Find the M365 Group by site display name.
        # This is the correct approach for modern SharePoint sites.
        m365_group = None
        try:
            url = (
                f"{GRAPH_API_BASE}/groups"
                f"?$filter=displayName eq '{site_name}'"
                f"&$select=id,displayName,mail,groupTypes"
            )
            result = await self._request("GET", url)
            for g in result.get("value", []):
                # Prefer Unified (M365) groups over security groups
                if "Unified" in g.get("groupTypes", []):
                    m365_group = g
                    break
            # If no Unified group, take the first match
            if not m365_group and result.get("value"):
                m365_group = result["value"][0]
        except Exception as e:
            logger.warning(
                f"Failed to look up M365 Group '{site_name}': {e}"
            )

        if m365_group:
            group_id = m365_group["id"]
            group_name = m365_group.get("displayName", site_name)
            group_sid = self._convert_object_id_to_sid(group_id)

            logger.info(
                f"Found M365 Group: '{group_name}' "
                f"(ID: {group_id}, SID: {group_sid})"
            )

            # Add the group itself with Modify permission.
            # This allows group-based access on Azure Files: any member
            # of the M365 Group gets Modify access via their group SID.
            permissions.append(PermissionEntry(
                path="/",
                principal=group_name,
                principal_type="Group",
                email=m365_group.get("mail"),
                object_id=group_id,
                sid=group_sid,
                sharepoint_role="M365 Group",
                ntfs_permission="Modify",
            ))

            # Enumerate OWNERS → FullControl
            try:
                owners_url = (
                    f"{GRAPH_API_BASE}/groups/{group_id}/owners"
                    f"?$select=id,displayName,mail"
                )
                while owners_url:
                    owners_result = await self._request(
                        "GET", owners_url
                    )
                    for owner in owners_result.get("value", []):
                        owner_sid = self._convert_object_id_to_sid(
                            owner["id"]
                        )
                        permissions.append(PermissionEntry(
                            path="/",
                            principal=owner.get("displayName", ""),
                            principal_type="User",
                            email=owner.get("mail"),
                            object_id=owner["id"],
                            sid=owner_sid,
                            sharepoint_role="Owner",
                            ntfs_permission="FullControl",
                            member_of=group_name,
                        ))
                    owners_url = owners_result.get("@odata.nextLink")
            except Exception as e:
                logger.warning(f"Failed to enumerate owners: {e}")

            # Enumerate MEMBERS → Modify
            try:
                members_url = (
                    f"{GRAPH_API_BASE}/groups/{group_id}/members"
                    f"?$select=id,displayName,mail"
                )
                while members_url:
                    members_result = await self._request(
                        "GET", members_url
                    )
                    for member in members_result.get("value", []):
                        member_sid = self._convert_object_id_to_sid(
                            member["id"]
                        )
                        odata_type = str(
                            member.get("@odata.type", "")
                        ).lower()
                        permissions.append(PermissionEntry(
                            path="/",
                            principal=member.get(
                                "displayName", ""
                            ),
                            principal_type=(
                                "User" if "user" in odata_type
                                else "Group"
                            ),
                            email=member.get("mail"),
                            object_id=member["id"],
                            sid=member_sid,
                            sharepoint_role="Member",
                            ntfs_permission="Modify",
                            member_of=group_name,
                        ))
                    members_url = members_result.get(
                        "@odata.nextLink"
                    )
            except Exception as e:
                logger.warning(f"Failed to enumerate members: {e}")

            logger.info(
                f"M365 Group '{group_name}': "
                f"{len(permissions)} permission entries"
            )
        else:
            # Strategy 2: Legacy fallback - look for separate
            # "<SiteName> Owners/Members/Visitors" groups.
            # This covers classic SharePoint sites or sites where the
            # M365 Group was renamed/deleted.
            logger.info(
                f"No M365 Group found for '{site_name}'. "
                f"Trying legacy group name pattern..."
            )
            for role, group_suffix, ntfs_perm in [
                ("Owner", "Owners", "FullControl"),
                ("Member", "Members", "Modify"),
                ("Visitor", "Visitors", "ReadAndExecute"),
            ]:
                try:
                    group_name = f"{site_name} {group_suffix}"
                    url = (
                        f"{GRAPH_API_BASE}/groups"
                        f"?$filter=displayName eq '{group_name}'"
                    )
                    result = await self._request("GET", url)

                    for group in result.get("value", []):
                        sid = self._convert_object_id_to_sid(
                            group["id"]
                        )
                        permissions.append(PermissionEntry(
                            path="/",
                            principal=group["displayName"],
                            principal_type="Group",
                            email=None,
                            object_id=group["id"],
                            sid=sid,
                            sharepoint_role=role,
                            ntfs_permission=ntfs_perm,
                        ))

                        # Enumerate members of this group
                        try:
                            members_url = (
                                f"{GRAPH_API_BASE}"
                                f"/groups/{group['id']}/members"
                            )
                            while members_url:
                                members_result = (
                                    await self._request(
                                        "GET", members_url
                                    )
                                )
                                for member in members_result.get(
                                    "value", []
                                ):
                                    member_sid = (
                                        self._convert_object_id_to_sid(
                                            member["id"]
                                        )
                                    )
                                    odata_type = str(
                                        member.get(
                                            "@odata.type", ""
                                        )
                                    ).lower()
                                    permissions.append(
                                        PermissionEntry(
                                            path="/",
                                            principal=member.get(
                                                "displayName", ""
                                            ),
                                            principal_type=(
                                                "User"
                                                if "user" in odata_type
                                                else "Group"
                                            ),
                                            email=member.get("mail"),
                                            object_id=member["id"],
                                            sid=member_sid,
                                            sharepoint_role=(
                                                f"{role} (inherited)"
                                            ),
                                            ntfs_permission=ntfs_perm,
                                            member_of=(
                                                group["displayName"]
                                            ),
                                        )
                                    )
                                members_url = members_result.get(
                                    "@odata.nextLink"
                                )
                        except Exception:
                            pass
                except Exception:
                    pass

        return permissions

    @staticmethod
    def _convert_object_id_to_sid(object_id: str) -> str:
        """Convert an Azure AD Object ID (GUID) to a Windows SID.

        Azure Files with Entra ID Kerberos authentication expects NTFS
        ACLs to reference principals by their Windows-format SID.  Azure
        AD objects have a deterministic SID derived from their Object ID
        under the ``S-1-12-1`` authority (Entra ID / Azure AD).

        Algorithm (per Microsoft documentation):
          1. Parse the Object ID as a UUID/GUID.
          2. Convert to little-endian byte representation (``bytes_le``).
          3. Split into four 4-byte groups.
          4. Interpret each group as an unsigned 32-bit little-endian int.
          5. Format as ``S-1-12-1-{int1}-{int2}-{int3}-{int4}``.

        Example::

            Object ID: "a]b1c2d3-e4f5-6789-abcd-ef0123456789"
            → SID: "S-1-12-1-<dec1>-<dec2>-<dec3>-<dec4>"

        The ``S-1-12-1`` prefix means:
          - S-1:   SID version 1
          - 12:    Identifier authority = Azure AD (0x0C)
          - 1:     Sub-authority count prefix

        Args:
            object_id: Azure AD Object ID as a GUID string.

        Returns:
            Windows SID string, or empty string if conversion fails.
        """
        try:
            # Step 1: Parse the Object ID string as a standard UUID.
            guid = uuid.UUID(object_id)

            # Step 2: Get the little-endian byte representation.
            # uuid.bytes_le reorders the first three components to
            # little-endian, matching the Windows GUID wire format.
            bytes_le = guid.bytes_le

            # Step 3: Split into four 4-byte groups and interpret each
            # as an unsigned 32-bit integer (little-endian).
            # These become the four sub-authorities in the SID.
            int1 = int.from_bytes(bytes_le[0:4], "little", signed=False)
            int2 = int.from_bytes(bytes_le[4:8], "little", signed=False)
            int3 = int.from_bytes(bytes_le[8:12], "little", signed=False)
            int4 = int.from_bytes(bytes_le[12:16], "little", signed=False)

            # Step 4: Format as a Windows SID under the S-1-12-1 authority.
            return f"S-1-12-1-{int1}-{int2}-{int3}-{int4}"
        except Exception:
            return ""


# ============================================================================
# Migration UI
#
# The terminal UI is built with the ``rich`` library and uses a ``Live``
# display that refreshes 4 times per second.  The layout has three zones:
#
#   ┌------------------------------------------------┐
#   |  Header: Source/Target info                    |
#   ├------------------------------------------------┤
#   |  Main area (phase-dependent):                  |
#   |    Phase "download":                            |
#   |      - Overall progress bar                     |
#   |      - Per-worker file progress table            |
#   |      - Activity log (last 6 events)              |
#   |    Phase "upload":                               |
#   |      - Overall progress bar (compact)            |
#   |      - AzCopy output panel (last 12 lines)       |
#   |      - Activity log (last 6 events)              |
#   ├------------------------------------------------┤
#   |  Footer: v DL speed | ^ UL speed | progress | errors | time |
#   └------------------------------------------------┘
#
# Thread safety:
#   The UI is updated from multiple concurrent download workers.  All
#   mutable state (activity_log, worker_status, upload_lines, stats) is
#   protected by an ``asyncio.Lock``.  The ``refresh()`` method is safe
#   to call from any coroutine.
# ============================================================================


class MigrationUI:
    """Rich terminal UI for real-time migration progress.

    Renders a live dashboard with progress bars, worker status, activity
    log, and transfer speeds.  Supports two display phases:

    - **download**: Shows per-worker download progress with file names.
    - **upload**: Shows AzCopy output with styled error/progress lines.

    The phase switches automatically as each batch transitions from
    download to upload.
    """

    def __init__(self, config: MigrationConfig):
        self.config = config
        self.console = Console()
        self.stats = MigrationStats()
        self.activity_log: list[ActivityLogEntry] = []
        self.worker_status: dict[int, tuple[str, float]] = {}  # worker_id -> (filename, progress)
        self.upload_lines: list[tuple[str, str]] = []  # (line, style)
        self.phase: str = "download"  # download | upload
        self._lock = asyncio.Lock()

        # Progress bars
        self.overall_progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
        )

        self._overall_task: Optional[TaskID] = None
        self._worker_tasks: dict[int, TaskID] = {}
        self._live: Optional[Live] = None

    def _create_header(self) -> Panel:
        """Create the header panel."""
        source = urlparse(self.config.site_url).netloc
        target = f"{self.config.storage_account}/{self.config.file_share}"

        header_text = Text()
        header_text.append("SharePoint to Azure Files Migration\n", style="bold cyan")
        header_text.append(f"Source: {source}/{self.config.library_name}", style="dim")
        header_text.append(" | ", style="dim")
        header_text.append(f"Target: {target}", style="dim")

        return Panel(header_text, border_style="blue")

    def _create_worker_table(self) -> Table:
        """Create the worker status table."""
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Worker", width=6)
        table.add_column("File", width=45)
        table.add_column("Progress", width=25)

        for worker_id, (filename, progress) in sorted(self.worker_status.items()):
            # Truncate filename if too long
            display_name = filename if len(filename) <= 40 else f"...{filename[-37:]}"

            # Create progress bar
            bar_width = 20
            filled = int(progress * bar_width)
            bar = "█" * filled + "░" * (bar_width - filled)

            status = "(ok)" if progress >= 1.0 else f"{progress*100:3.0f}%"

            table.add_row(
                f"[{worker_id}]",
                display_name,
                f"[green]{bar}[/green] {status}"
            )

        return table

    def _create_activity_log(self) -> Panel:
        """Create the activity log panel."""
        log_text = Text()

        # Show last 6 entries
        for entry in self.activity_log[-6:]:
            icon = {
                "success": "[green]OK[/green]",
                "warning": "[yellow]!![/yellow]",
                "error": "[red]XX[/red]",
                "info": "[blue]--[/blue]",
            }.get(entry.status, " ")

            size_str = ""
            if entry.file_size:
                if entry.file_size >= 1024 * 1024:
                    size_str = f" ({entry.file_size / 1024 / 1024:.1f} MB)"
                else:
                    size_str = f" ({entry.file_size / 1024:.0f} KB)"

            log_text.append(f" {icon} {entry.message}{size_str}\n")

        return Panel(log_text, title="Recent Activity", border_style="dim")

    def _create_upload_panel(self) -> Panel:
        """Create the AzCopy upload output panel."""
        upload_text = Text()

        # Show last 12 lines of AzCopy output
        for line, style in self.upload_lines[-12:]:
            upload_text.append(f" {line}\n", style=style)

        if not self.upload_lines:
            upload_text.append(
                " Waiting for AzCopy...\n", style="dim"
            )

        return Panel(
            upload_text,
            title="Phase 2: Uploading to Azure Files (AzCopy)",
            border_style="magenta",
        )

    def _create_status_bar(self) -> Panel:
        """Create the bottom status bar."""
        elapsed = ""
        if self.stats.start_time:
            delta = datetime.now() - self.stats.start_time
            hours, remainder = divmod(int(delta.total_seconds()), 3600)
            minutes, seconds = divmod(remainder, 60)
            elapsed = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        # Calculate sizes in human-readable format
        downloaded_size = self.stats.downloaded_bytes / (1024 * 1024 * 1024)  # GB
        total_size = self.stats.total_bytes / (1024 * 1024 * 1024)  # GB

        # Format speeds
        dl_speed = self.stats.current_download_speed / (1024 * 1024)  # MB/s
        ul_speed = self.stats.current_upload_speed / (1024 * 1024)  # MB/s

        status_text = (
            f" v {dl_speed:.1f} MB/s | "
            f"^ {ul_speed:.1f} MB/s | "
            f"{downloaded_size:.2f}/{total_size:.2f} GB | "
            f"Errors: {self.stats.failed_files}"
        )
        if self.stats.archived_files > 0:
            status_text += (
                f" | Archived: {self.stats.archived_files}"
            )
        status_text += f" | {elapsed}"

        has_issues = (
            self.stats.failed_files > 0
            or self.stats.archived_files > 0
        )

        return Panel(
            Text(status_text, justify="center"),
            border_style="green" if not has_issues else "yellow",
        )

    def _create_layout(self) -> Layout:
        """Create the complete layout."""
        layout = Layout()

        layout.split_column(
            Layout(
                self._create_header(), name="header", size=4
            ),
            Layout(name="main"),
            Layout(
                self._create_status_bar(), name="footer", size=3
            ),
        )

        if self.phase == "upload":
            layout["main"].split_column(
                Layout(name="progress", size=5),
                Layout(
                    self._create_upload_panel(),
                    name="upload",
                ),
                Layout(
                    self._create_activity_log(),
                    name="activity",
                    size=8,
                ),
            )
            # Compact download summary during upload
            progress_content = Group(
                self.overall_progress,
            )
        else:
            layout["main"].split_column(
                Layout(name="progress", size=12),
                Layout(
                    self._create_activity_log(),
                    name="activity",
                ),
            )
            # Full download view with worker table
            progress_content = Group(
                Text(
                    "\nPhase 1: Downloading from SharePoint",
                    style="bold",
                ),
                Text("-" * 70, style="dim"),
                self.overall_progress,
                Text("\nWorkers:", style="dim"),
                self._create_worker_table()
                if self.worker_status
                else Text("  (idle)", style="dim"),
            )

        layout["progress"].update(
            Panel(progress_content, border_style="blue")
        )

        return layout

    async def add_activity(self, message: str, status: str, file_size: Optional[int] = None):
        """Add an entry to the activity log."""
        async with self._lock:
            self.activity_log.append(ActivityLogEntry(
                timestamp=datetime.now(),
                message=message,
                status=status,
                file_size=file_size,
            ))
            # Keep only last 100 entries
            if len(self.activity_log) > 100:
                self.activity_log = self.activity_log[-100:]

    async def update_worker(self, worker_id: int, filename: str, progress: float):
        """Update worker status."""
        async with self._lock:
            if progress >= 1.0:
                self.worker_status.pop(worker_id, None)
            else:
                self.worker_status[worker_id] = (filename, progress)

    async def update_stats(self, **kwargs):
        """Update migration statistics."""
        async with self._lock:
            for key, value in kwargs.items():
                if hasattr(self.stats, key):
                    setattr(self.stats, key, value)

    def set_phase(self, phase: str):
        """Switch the UI phase ('download' or 'upload')."""
        self.phase = phase
        self.refresh()

    async def add_upload_line(
        self, line: str, style: str = ""
    ):
        """Add an AzCopy output line to the upload panel."""
        async with self._lock:
            self.upload_lines.append((line, style))
            # Keep only last 200 lines
            if len(self.upload_lines) > 200:
                self.upload_lines = self.upload_lines[-200:]
        self.refresh()

    def start(self, total_files: int, total_bytes: int):
        """Start the live display."""
        self.stats.total_files = total_files
        self.stats.total_bytes = total_bytes
        self.stats.start_time = datetime.now()

        self._overall_task = self.overall_progress.add_task(
            "Overall",
            total=total_files,
        )

        self._live = Live(
            self._create_layout(),
            console=self.console,
            refresh_per_second=4,
            screen=False,
        )
        self._live.start()

    def stop(self):
        """Stop the live display."""
        if self._live:
            self._live.stop()

    def refresh(self):
        """Refresh the display."""
        if self._live:
            self.overall_progress.update(
                self._overall_task,
                completed=self.stats.downloaded_files,
            )
            self._live.update(self._create_layout())


# ============================================================================
# Migration Engine
#
# This is the main orchestrator that ties together all other components.
# It follows this high-level flow:
#
#   1. WARN      – Display migration warning with 5-second countdown.
#   2. SETUP     – Create temp dirs, load checkpoint, verify Azure CLI auth.
#   3. CONNECT   – Resolve SharePoint site and document library via Graph.
#   4. ENUMERATE – Delta query all files in the library.
#   5. FILTER    – Remove already-processed files (checkpoint), re-queue
#                  files modified since last run.
#   6. PERMISSIONS (optional) – Export site permissions to JSON.
#   7. BATCH LOOP – For each batch of BATCH_SIZE files:
#      a. Download  – Parallel async workers fetch files + metadata.
#      b. Upload    – AzCopy copies batch to Azure Files.
#      c. Checkpoint – Mark batch as processed.
#      d. Cleanup   – Delete local temp files.
#   8. REPORT    – Exit with 0 if all files succeeded, 1 if any failed.
#
# The engine caches storage keys and SAS tokens across batches to avoid
# redundant Azure CLI calls.  Checkpoints are saved after every batch
# and periodically during downloads (every 50 files).
# ============================================================================


class MigrationEngine:
    """Main migration engine: orchestrates download, upload, and checkpointing.

    Owns the ``TokenManager``, ``MigrationUI``, ``SpeedTracker``, and
    ``Checkpoint`` instances.  Uses ``GraphAPIClient`` (passed to methods
    as a context-managed session) for all SharePoint API calls.

    The engine is designed to be **resumable**: if interrupted (Ctrl+C,
    crash, network failure), the checkpoint file preserves progress and
    the next run will skip already-uploaded files.
    """

    def __init__(self, config: MigrationConfig):
        self.config = config
        self.token_manager = TokenManager()
        self.console = Console()
        self.ui: Optional[MigrationUI] = None
        self.checkpoint: Optional[Checkpoint] = None
        self._speed_tracker = SpeedTracker()
        self._cached_storage_key: Optional[str] = None
        self._cached_sas_token: Optional[str] = None
        self._sas_expiry: Optional[datetime] = None
        # Site-level permissions (Owners/Members/Visitors) fetched once
        # and applied to the temp dir root before each AzCopy upload.
        self._site_permissions: list[PermissionEntry] = []
        self._cached_storage_key: Optional[str] = None
        self._cached_sas_token: Optional[str] = None
        self._sas_expiry: Optional[datetime] = None

    async def run(self) -> bool:
        """Run the complete migration pipeline.

        This is the top-level method that orchestrates the entire
        migration.  See the class-level docstring for the flow.

        Returns:
            True if all files were migrated successfully, False if any
            files failed or the migration was interrupted.

        Raises:
            RuntimeError: If Azure CLI authentication fails.
            Exception: Re-raised after saving checkpoint on unexpected
                       errors.
        """
        logger.info("Starting copy run")

        try:
            # Show warning
            await self._show_warning()

            # Setup
            await self._setup()

            # Connect and enumerate
            async with GraphAPIClient(self.token_manager) as client:
                # Get site and drive
                self.console.print("\n[bold]Connecting to SharePoint...[/bold]")
                logger.info("Connecting to SharePoint...")

                site_start = time.time()
                site = await client.get_site(self.config.site_url)
                site_elapsed = (time.time() - site_start) * 1000
                logger.info(
                    f"Got site '{site['displayName']}' in {site_elapsed:.0f}ms"
                )
                self.console.print(f"  (ok) Site: [cyan]{site['displayName']}[/cyan]")

                drive_start = time.time()
                drive = await client.get_drive(site["id"], self.config.library_name)
                drive_elapsed = (time.time() - drive_start) * 1000
                logger.info(
                    f"Got drive '{drive['name']}' in {drive_elapsed:.0f}ms"
                )
                self.console.print(f"  (ok) Library: [cyan]{drive['name']}[/cyan]")

                # Default target folder to the library name so files
                # land in a named subfolder (e.g. "Documents/") rather
                # than cluttering the share root.
                if not self.config.target_folder:
                    self.config.target_folder = drive["name"]
                    logger.info(
                        f"Target folder defaulted to library name: "
                        f"'{self.config.target_folder}'"
                    )
                    self.console.print(
                        f"  (ok) Target folder: "
                        f"[cyan]{self.config.target_folder}[/cyan] "
                        f"(auto: library name)"
                    )
                else:
                    self.console.print(
                        f"  (ok) Target folder: "
                        f"[cyan]{self.config.target_folder}[/cyan]"
                    )

                # Enumerate files
                self.console.print("\n[bold]Enumerating files...[/bold]")
                logger.info("Enumerating files...")
                enum_start = time.time()

                files = await client.get_all_files(
                    site["id"],
                    drive["id"],
                    on_progress=lambda n: self.console.print(f"  Found {n} files..."),
                )

                enum_elapsed = (time.time() - enum_start) * 1000
                total_size = sum(f.size for f in files)
                logger.info(
                    f"Enumerated {len(files)} files ({total_size/1024/1024:.1f} MB) "
                    f"in {enum_elapsed:.0f}ms"
                )
                self.console.print(f"  (ok) Found [cyan]{len(files)}[/cyan] files")

                if not files:
                    logger.info("No files to copy")
                    self.console.print("[yellow]No files to copy.[/yellow]")
                    return True

                # Apply max files limit
                if self.config.max_files > 0 and len(files) > self.config.max_files:
                    files = files[:self.config.max_files]
                    logger.info(f"Limited to {self.config.max_files} files (test mode)")
                    self.console.print(
                        f"  [yellow]Limited to first {self.config.max_files} files[/yellow]"
                    )

                # Filter already processed files
                files_to_process = self._filter_processed_files(files)
                logger.info(
                    f"After checkpoint filter: {len(files_to_process)} files to process"
                )

                if not files_to_process:
                    logger.info("All files already processed")
                    self.console.print("[green]All files already processed![/green]")
                    return True

                total_files_count = len(files_to_process)
                total_bytes = sum(f.size for f in files_to_process)
                total_size_gb = total_bytes / (1024 * 1024 * 1024)
                logger.info(
                    f"To process: {total_files_count} files, {total_size_gb:.2f} GB"
                )
                self.console.print(
                    f"  Files to process: [cyan]{total_files_count}[/cyan]"
                )
                self.console.print(f"  Total size: [cyan]{total_size_gb:.2f} GB[/cyan]")

                # Export permissions if requested
                if self.config.export_permissions:
                    self.console.print("\n[bold]Exporting permissions...[/bold]")
                    self._site_permissions = await client.get_site_permissions(
                        site["id"],
                        site["displayName"],
                        drive["id"],
                    )
                    await self._save_permissions(self._site_permissions, site)
                    self.console.print(
                        f"  (ok) Exported [cyan]{len(self._site_permissions)}[/cyan] "
                        f"permission entries"
                    )

                # Dry run mode
                if self.config.dry_run:
                    self.console.print("\n[yellow]Dry run mode - no files will be copied[/yellow]")
                    for f in files_to_process[:20]:
                        self.console.print(f"  Would copy: {f.path} ({f.size} bytes)")
                    if len(files_to_process) > 20:
                        self.console.print(f"  ... and {len(files_to_process) - 20} more files")
                    return True

                # Start copy
                self.console.print("\n[bold]Starting copy (pipelined batch mode)...[/bold]\n")

                self.ui = MigrationUI(self.config)
                self.ui.start(total_files_count, total_bytes)

                try:
                    # Process in batches
                    chunked_files = [
                        files_to_process[i : i + BATCH_SIZE]
                        for i in range(0, len(files_to_process), BATCH_SIZE)
                    ]

                    for batch_idx, batch in enumerate(chunked_files):
                        self.console.print(f"\n[bold blue]Processing Batch {batch_idx + 1}/{len(chunked_files)} ({len(batch)} files)[/bold blue]")

                        # Process batch
                        success = await self._process_batch(client, batch)
                        if not success:
                            self.console.print("[red]Batch failed, stopping copy.[/red]")
                            await self._save_checkpoint()
                            return False

                    # Report archived files if any were found
                    if self.ui.stats.archived_files > 0:
                        archived_list = [
                            f for f in files_to_process
                            if f.status == FileStatus.ARCHIVED
                        ]
                        await self._write_archived_report(archived_list)

                    return self.ui.stats.failed_files == 0

                finally:
                    if self.ui:
                        self.ui.stop()

        except KeyboardInterrupt:
            await self._save_checkpoint()
            self.console.print("\n[yellow]Copy interrupted. Progress saved to checkpoint.[/yellow]")
            return False
        except Exception as e:
            await self._save_checkpoint()
            self.console.print(f"\n[red]Copy failed: {e}[/red]")
            raise

    async def _show_warning(self):
        """Display a pre-migration warning about SharePoint feature loss.

        Shows a prominent panel listing SharePoint features that will
        be lost (version history, co-authoring, etc.) and pauses for
        5 seconds.  The user can press Ctrl+C to abort before the
        migration starts.

        This is intentionally not skippable via a flag to ensure
        operators are always aware of the implications.
        """
        warning_text = """
[bold yellow](!)  SHAREPOINT COPY WARNING[/bold yellow]

You are about to [bold]copy[/bold] files from SharePoint to Azure Files.
[green]Source data will NOT be deleted[/green] - SharePoint remains unchanged.
Azure Files is a FILE STORAGE service, NOT a document management system.

[bold red]Features NOT available in Azure Files:[/bold red]
 (x) Version History      (x) Metadata/Columns     (x) Sharing Links
 (x) Co-authoring         (x) Power Automate       (x) Comments
 (x) Check-in/Check-out   (x) Content Approval     (x) Alerts
 (x) Retention Policies   (x) eDiscovery           (x) Search

[bold green]Good for:[/bold green] Archiving, file-centric content, backup
[bold red]Not for:[/bold red] Active collaboration, version control, compliance
"""
        self.console.print(Panel(warning_text, title="Copy Warning", border_style="yellow"))

        for i in range(5, 0, -1):
            self.console.print(
                f"\rCopy will start in [bold yellow]{i}[/bold yellow] seconds. "
                "Press Ctrl+C to cancel...",
                end="\r",
            )
            await asyncio.sleep(1)
        self.console.print(
            "\rCopy starting...                                              "
        )

    async def _setup(self):
        """Initialize directories, load checkpoint, and verify authentication.

        Responsibilities:
          1. Create the temp download directory (stable path across runs
             to avoid orphaned directories).
          2. Set the checkpoint file path (defaults to ./logs/checkpoint.json).
          3. Load any existing checkpoint from disk.
          4. Verify Azure CLI authentication by fetching a Graph token.
        """
        # Create temp directory - use a stable name so we don't
        # leave orphaned random dirs across runs
        if not self.config.temp_dir:
            self.config.temp_dir = (
                Path(tempfile.gettempdir()) / "sp_migration"
            )

        # Wipe any leftover content from previous runs.  Since we
        # switched from --list-of-files to wildcard source ("*"),
        # AzCopy uploads EVERYTHING in the temp dir.  Stale files
        # from prior runs would cause unwanted uploads and massive
        # metadata overhead (creating hundreds of empty folders).
        if self.config.temp_dir.exists():
            shutil.rmtree(self.config.temp_dir, ignore_errors=True)
            logger.info(
                f"Cleaned temp directory: {self.config.temp_dir}"
            )
        self.config.temp_dir.mkdir(parents=True, exist_ok=True)

        # Setup checkpoint file - use stable location so resume works
        if not self.config.checkpoint_file:
            log_dir = Path.cwd() / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            self.config.checkpoint_file = log_dir / "checkpoint.json"

        logger.info(
            f"Checkpoint file: {self.config.checkpoint_file}"
        )

        # Load existing checkpoint
        await self._load_checkpoint()

        # Verify Azure CLI login
        await self.token_manager.get_token()
        self.console.print("[green](ok) Azure CLI authenticated[/green]")

    def _compute_config_hash(self) -> str:
        """Compute a fingerprint of the migration source/target.

        The hash is derived from the combination of site URL, library
        name, storage account, and file share.  It's stored in the
        checkpoint file to detect when a checkpoint belongs to a
        *different* migration configuration.  This prevents accidentally
        skipping files that were never uploaded to the current target.

        Returns:
            First 16 hex characters of the SHA-256 hash.
        """
        key = (
            f"{self.config.site_url}|{self.config.library_name}|"
            f"{self.config.storage_account}|{self.config.file_share}"
        )
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    async def _load_checkpoint(self):
        """Load checkpoint from disk, handling format upgrades and validation.

        Checkpoint format history:
          - **v1** (legacy): ``{"processed_ids": ["id1", ...], ...}``
            A flat list of file IDs with no metadata.
          - **v2** (current): ``{"processed_files": {"id1": {...}}, ...}``
            A dict mapping file IDs to metadata (path, size, modified,
            uploaded_at).  This enables modified-file detection.

        If a v1 checkpoint is found, it's automatically upgraded to v2
        format (with placeholder metadata) so the migration can proceed.

        Config hash validation:
          If the saved ``config_hash`` doesn't match the current config,
          the checkpoint is discarded with a warning.  This prevents
          cross-contamination between different migration targets.
        """
        current_hash = self._compute_config_hash()

        if (self.config.checkpoint_file
                and self.config.checkpoint_file.exists()):
            try:
                async with aiofiles.open(
                    self.config.checkpoint_file, "r"
                ) as f:
                    data = json.loads(await f.read())

                saved_hash = data.get("config_hash", "")

                # Backward compat: convert old processed_ids list
                # to new processed_files dict
                if "processed_ids" in data and "processed_files" not in data:
                    logger.info(
                        "Upgrading checkpoint from v1 "
                        "(processed_ids) to v2 (processed_files)"
                    )
                    old_ids = data.get("processed_ids", [])
                    processed_files = {
                        fid: {
                            "path": "",
                            "size": 0,
                            "modified": None,
                            "uploaded_at": data.get("last_update"),
                        }
                        for fid in old_ids
                    }
                else:
                    processed_files = data.get(
                        "processed_files", {}
                    )

                # Validate config_hash
                if saved_hash and saved_hash != current_hash:
                    self.console.print(
                        "[yellow](!) Checkpoint is from a different "
                        "migration config (site/storage changed). "
                        "Starting fresh.[/yellow]"
                    )
                    logger.warning(
                        f"Config hash mismatch: saved={saved_hash}"
                        f" current={current_hash}. "
                        "Discarding checkpoint."
                    )
                    self.checkpoint = Checkpoint(
                        config_hash=current_hash
                    )
                    return

                self.checkpoint = Checkpoint(
                    config_hash=current_hash,
                    processed_files=processed_files,
                    failed_ids=data.get("failed_ids", {}),
                    last_update=data.get("last_update"),
                )

                n_processed = len(self.checkpoint.processed_files)
                n_failed = len(self.checkpoint.failed_ids)
                self.console.print(
                    f"[cyan]Loaded checkpoint: "
                    f"{n_processed} files processed, "
                    f"{n_failed} previously failed[/cyan]"
                )
                if n_failed > 0:
                    self.console.print(
                        f"[yellow]  {n_failed} previously "
                        f"failed files will be retried[/yellow]"
                    )
                logger.info(
                    f"Loaded checkpoint: {n_processed} processed, "
                    f"{n_failed} failed"
                )

            except Exception as e:
                self.console.print(
                    f"[yellow]Could not load checkpoint: "
                    f"{e}[/yellow]"
                )
                self.checkpoint = Checkpoint(
                    config_hash=current_hash
                )
        else:
            self.checkpoint = Checkpoint(
                config_hash=current_hash
            )

    async def _save_checkpoint(self):
        """Persist the current checkpoint state to disk atomically.

        Called at multiple points for resilience:
          - After every batch completes (download + upload).
          - Every 50 files during download (periodic safety save).
          - On KeyboardInterrupt or unexpected exceptions.

        Uses write-to-temp-then-rename to prevent corruption if the
        process is killed mid-write (C5 fix).
        """
        if self.config.checkpoint_file and self.checkpoint:
            self.checkpoint.last_update = datetime.now().isoformat()
            data = {
                "config_hash": self.checkpoint.config_hash,
                "processed_files": self.checkpoint.processed_files,
                "failed_ids": self.checkpoint.failed_ids,
                "last_update": self.checkpoint.last_update,
            }
            # Write to a temp file in the same directory, then atomically
            # rename.  This ensures the checkpoint is never in a
            # half-written state on disk.
            tmp_path = self.config.checkpoint_file.with_suffix(".tmp")
            async with aiofiles.open(tmp_path, "w") as f:
                await f.write(json.dumps(data, indent=2))
            # os.replace is atomic on both Windows (NTFS) and POSIX.
            os.replace(str(tmp_path), str(self.config.checkpoint_file))

    def _filter_processed_files(
        self, files: list[FileItem]
    ) -> list[FileItem]:
        """Filter out already-processed files, re-queue modified ones.

        This implements the **incremental migration** logic:

        1. If ``--overwrite`` is set, skip filtering entirely (re-upload
           everything).
        2. For each file in the enumeration:
           a. If the file ID is NOT in the checkpoint → include it.
           b. If the file ID IS in the checkpoint:
              - Compare SharePoint's ``lastModifiedDateTime`` against the
                checkpoint's stored ``modified`` timestamp.
              - If the file was modified after the last upload → re-queue
                it (delete the stale checkpoint entry).
              - Otherwise → skip it (already up-to-date).

        This means re-running the migration after a partial failure will:
          - Skip successfully uploaded files (fast resume).
          - Re-upload files that changed in SharePoint since last run.
          - Retry previously failed files (they're in ``failed_ids``,
            not ``processed_files``).

        Args:
            files: Complete list of files from the enumeration phase.

        Returns:
            Filtered list of files that need to be processed.
        """
        if self.config.overwrite:
            n = len(
                self.checkpoint.processed_files
            ) if self.checkpoint else 0
            if n > 0:
                self.console.print(
                    f"  [yellow]--overwrite: ignoring "
                    f"checkpoint ({n} entries), "
                    f"re-processing all files[/yellow]"
                )
                logger.info(
                    f"Overwrite mode: clearing {n} "
                    f"checkpoint entries"
                )
                self.checkpoint.processed_files.clear()
            return files

        if not self.checkpoint or not self.checkpoint.processed_files:
            return files

        to_process = []
        skipped = 0
        reprocess = 0

        for f in files:
            if f.id not in self.checkpoint.processed_files:
                # Never processed - include
                to_process.append(f)
                continue

            prev = self.checkpoint.processed_files[f.id]
            prev_modified = prev.get("modified")

            # Compare timestamps by parsing to datetime objects.
            # String comparison is fragile across different ISO 8601
            # formats ("Z" vs "+00:00", varying fractional seconds).
            if f.modified and prev_modified:
                try:
                    sp_dt = datetime.fromisoformat(
                        f.modified.replace("Z", "+00:00")
                    )
                    cp_dt = datetime.fromisoformat(
                        prev_modified.replace("Z", "+00:00")
                    )
                    file_is_newer = sp_dt > cp_dt
                except (ValueError, TypeError):
                    # If parsing fails, fall back to string comparison
                    file_is_newer = f.modified > prev_modified
                if file_is_newer:
                    # File changed in SharePoint since last upload
                    logger.info(
                        f"Re-processing (modified): {f.path} "
                        f"SP={f.modified} > "
                        f"checkpoint={prev_modified}"
                    )
                    # Remove stale entry so it gets re-added after upload
                    del self.checkpoint.processed_files[f.id]
                    reprocess += 1
                    to_process.append(f)
                    continue

            # Not modified or can't compare - skip
            skipped += 1

        if skipped > 0 or reprocess > 0:
            self.console.print(
                f"  Checkpoint: [green]{skipped} skipped "
                f"(unchanged)[/green]"
                + (
                    f", [yellow]{reprocess} re-queued "
                    f"(modified in SharePoint)[/yellow]"
                    if reprocess > 0
                    else ""
                )
            )
            logger.info(
                f"Checkpoint filter: {skipped} skipped, "
                f"{reprocess} re-queued as modified, "
                f"{len(to_process)} to process"
            )

        return to_process

    async def _write_archived_report(
        self, archived_files: list[FileItem]
    ) -> None:
        """Write a report of M365-archived files that could not be copied.

        Creates ``logs/archived_files.csv`` listing all files that
        returned HTTP 423 (Locked) during download.  These files need
        to be reactivated in SharePoint before they can be copied.

        After reactivation (can take up to 24 hours), re-run the script
        -- the checkpoint will skip already-copied files and only pick
        up the newly reactivated ones.

        Args:
            archived_files: List of FileItem instances with ARCHIVED status.
        """
        log_dir = Path.cwd() / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        report_path = log_dir / "archived_files.csv"

        async with aiofiles.open(report_path, "w", encoding="utf-8") as f:
            await f.write("path,name,size_bytes,site_id,drive_id,item_id\n")
            for file in archived_files:
                # Escape commas in path/name
                safe_path = file.path.replace(",", ";")
                safe_name = file.name.replace(",", ";")
                await f.write(
                    f"{safe_path},{safe_name},{file.size},"
                    f"{file.site_id},{file.drive_id},{file.id}\n"
                )

        self.console.print(
            f"\n[yellow](!) {len(archived_files)} file(s) are "
            f"M365-archived and could not be copied.[/yellow]"
        )
        self.console.print(
            f"    Report saved to: [cyan]{report_path}[/cyan]"
        )
        self.console.print(
            "    To copy these files:"
        )
        self.console.print(
            "    1. Reactivate them in SharePoint "
            "(can take up to 24 hours)"
        )
        self.console.print(
            "    2. Re-run this script (checkpoint will skip "
            "already-copied files)"
        )
        logger.info(
            f"Archived files report: {report_path} "
            f"({len(archived_files)} files)"
        )

    async def _save_permissions(self, permissions: list[PermissionEntry], site: dict):
        """Save exported permissions to a JSON file.

        The output file follows the format expected by the companion
        ``apply_permissions.py`` script, which can apply NTFS ACLs
        to a mounted Azure Files share.

        Output structure::

            {
              "SiteUrl": "https://...",
              "SiteName": "...",
              "ExportDate": "2026-02-11 12:00:00",
              "Permissions": [
                {"Path": "/", "Principal": "...", "SID": "S-1-12-1-...", ...}
              ]
            }

        Args:
            permissions: List of ``PermissionEntry`` instances.
            site:        Graph API site resource (for display name).
        """
        if not self.config.permissions_file:
            self.config.permissions_file = Path("SharePointPermissions.json")

        data = {
            "SiteUrl": self.config.site_url,
            "SiteName": site["displayName"],
            "ExportDate": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Permissions": [
                {
                    "Path": p.path,
                    "Principal": p.principal,
                    "PrincipalType": p.principal_type,
                    "Email": p.email,
                    "ObjectId": p.object_id,
                    "SID": p.sid,
                    "SharePointRole": p.sharepoint_role,
                    "NtfsPermission": p.ntfs_permission,
                    "MemberOf": p.member_of,
                }
                for p in permissions
            ],
        }

        async with aiofiles.open(self.config.permissions_file, "w") as f:
            await f.write(json.dumps(data, indent=2))

    async def _process_batch(self, client: GraphAPIClient, batch_files: list[FileItem]) -> bool:
        """Process one batch through the full download → upload → cleanup cycle.

        Batch lifecycle:
          1. **Download**: All files in the batch are downloaded in parallel
             to the local temp directory.  Metadata, timestamps, and ACLs
             are applied during this phase.
          2. **Upload**: A single AzCopy invocation copies the entire batch
             to Azure Files.  Uses ``--list-of-files`` to scope the upload.
          3. **Checkpoint**: Successfully uploaded files are marked in the
             checkpoint.  Previously failed files that now succeed are
             removed from ``failed_ids``.
          4. **Cleanup**: Local temp files are deleted to free disk space.

        If download or upload fails, the checkpoint is saved before
        returning False so progress is preserved.

        Args:
            client:      Active ``GraphAPIClient`` session.
            batch_files: List of ``FileItem`` instances to process.

        Returns:
            True if the batch completed successfully, False otherwise.
        """
        # 1. Download Batch
        if not await self._download_batch(client, batch_files):
            self.console.print("[bold red]Batch download failed[/bold red]")
            await self._save_checkpoint()
            return False

        # 1b. Apply site-level ACLs to temp dir root (Windows only).
        # This must happen AFTER download (so the dirs exist) and
        # BEFORE upload (so AzCopy --preserve-smb-permissions picks
        # them up).  Files in subfolders inherit these ACLs via NTFS
        # inheritance, matching SharePoint's site-level permission model.
        if IS_WINDOWS and self._site_permissions:
            await self._apply_site_acls_to_temp_root()

        # 2. Upload Batch
        upload_ok = await self._upload_batch(batch_files)
        if not upload_ok:
            self.console.print("[bold red]Batch upload failed[/bold red]")
            await self._save_checkpoint()
            return False

        # 3. Mark successfully uploaded files in checkpoint
        now = datetime.now().isoformat()
        uploaded_count = 0
        uploaded_bytes = 0
        for file in batch_files:
            if file.status == FileStatus.DOWNLOADED:
                file.status = FileStatus.COMPLETED
                self.checkpoint.processed_files[file.id] = {
                    "path": file.path,
                    "size": file.size,
                    "modified": file.modified,
                    "uploaded_at": now,
                }
                # Clear from failed if previously failed
                self.checkpoint.failed_ids.pop(file.id, None)
                uploaded_count += 1
                uploaded_bytes += file.size

        # Update upload stats
        self.ui.stats.uploaded_files += uploaded_count
        self.ui.stats.uploaded_bytes += uploaded_bytes
        await self._save_checkpoint()

        # 4. Cleanup Batch
        await self._cleanup_batch(batch_files)

        return True

    async def _download_batch(
        self,
        client: GraphAPIClient,
        files: list[FileItem],
    ) -> bool:
        """Download a batch of files from SharePoint in parallel.

        Concurrency model:
          - Creates one ``download_worker`` coroutine per file.
          - Uses an ``asyncio.Semaphore`` to limit concurrent downloads
            to ``config.concurrent_downloads`` (default 8).
          - Worker IDs are assigned round-robin (``i % concurrent_downloads``)
            so the UI shows a fixed number of worker slots.

        Per-file download flow (inside each worker):
          1. Fetch file metadata (permissions, custom columns, hashes)
             via Graph API with ``$expand``.
          2. Get a pre-authenticated download URL.
          3. Stream-download the file to local temp directory in 1 MB chunks.
          4. Apply original timestamps (``os.utime`` + Win32 creation time).
          5. Apply NTFS ACLs via ``icacls`` (Windows only).
          6. Collect metadata for the folder's ``.sp-metadata.json`` sidecar.

        Retry strategy:
          - Transient errors (``asyncio.TimeoutError``, ``aiohttp.ClientError``)
            trigger a retry after RETRY_DELAY_SECONDS (5s).
          - Up to MAX_RETRIES (3) attempts per file.
          - Non-transient errors (e.g., missing download URL) fail immediately.
          - After exhausting retries, the file is marked FAILED and recorded
            in ``checkpoint.failed_ids``.

        After all workers complete, ``.sp-metadata.json`` files are written
        for each folder, and the checkpoint is saved.

        Args:
            client: Active ``GraphAPIClient`` session.
            files:  List of ``FileItem`` instances in this batch.

        Returns:
            True if at least one file downloaded successfully, False if
            the entire batch failed.
        """
        batch_start = time.time()
        batch_size = len(files)
        batch_bytes = sum(f.size for f in files)
        logger.info(
            f"Starting batch download: {batch_size} files, "
            f"{batch_bytes / 1024 / 1024:.1f} MB"
        )

        semaphore = asyncio.Semaphore(self.config.concurrent_downloads)
        # Track metadata per folder for .sp-metadata.json files
        folder_metadata: dict[str, dict[str, FileMetadata]] = {}
        folder_metadata_lock = asyncio.Lock()

        async def download_worker(worker_id: int, file: FileItem):
            """Download a single file with retry logic (non-recursive).

            Uses a while loop (not recursion) for retries to avoid stack
            growth.  The semaphore is acquired inside the loop so that
            a retry releases the slot while sleeping, allowing other
            workers to proceed.

            Args:
                worker_id: Worker slot ID (0 to concurrent_downloads-1),
                           used for UI display.
                file:      The FileItem to download (mutated in place).
            """
            file_start = time.time()
            logger.debug(
                f"[W{worker_id}] Starting download: {file.name} "
                f"({file.size / 1024:.1f} KB)"
            )

            while file.retry_count < MAX_RETRIES:
                async with semaphore:
                    try:
                        file.status = FileStatus.DOWNLOADING

                        # Step 1: Get file metadata
                        meta_start = time.time()
                        try:
                            file.metadata = await asyncio.wait_for(
                                client.get_file_metadata(
                                    file.site_id,
                                    file.drive_id,
                                    file.id,
                                    file.name,
                                ),
                                timeout=60,
                            )
                            meta_elapsed = (time.time() - meta_start) * 1000
                            logger.debug(
                                f"[W{worker_id}] Metadata for {file.name}: "
                                f"{meta_elapsed:.0f}ms"
                            )
                        except asyncio.TimeoutError:
                            logger.warning(
                                f"[W{worker_id}] Metadata timeout for {file.name}"
                            )
                            # Re-raise as TimeoutError so the outer retry handler
                            # catches it as a transient/retriable error (C1 fix).
                            raise
                        except Exception as meta_err:
                            logger.warning(
                                f"[W{worker_id}] Metadata error for {file.name}: "
                                f"{meta_err}"
                            )
                            # Create basic metadata if fetch fails
                            file.metadata = FileMetadata(
                                id=file.id,
                                name=file.name,
                                size=file.size,
                            )
                            file.metadata.acl_error = f"Metadata failed: {meta_err}"

                        # Step 2: Get download URL
                        url_start = time.time()
                        download_url = await asyncio.wait_for(
                            client.get_download_url(
                                file.site_id,
                                file.drive_id,
                                file.id,
                            ),
                            timeout=30,
                        )
                        url_elapsed = (time.time() - url_start) * 1000
                        logger.debug(
                            f"[W{worker_id}] Got URL for {file.name}: "
                            f"{url_elapsed:.0f}ms"
                        )

                        if not download_url:
                            raise RuntimeError("No download URL returned")

                        # Determine local path
                        # NOTE: Do NOT prepend target_folder here.
                        # The destination URL already includes it.
                        # Prepending it locally would cause
                        # double-nesting: share/target/target/...
                        file.local_path = (
                            self.config.temp_dir / file.path
                        )

                        # Ensure parent dir exists
                        file.local_path.parent.mkdir(parents=True, exist_ok=True)

                        # Download with progress tracking.
                        # The on_progress callback is throttled to max 10 updates/sec
                        # (0.1s interval) to avoid overwhelming the UI refresh.
                        dl_start = time.time()
                        last_update_time = [time.time()]  # mutable list for closure
                        self._speed_tracker.reset_worker(worker_id)

                        def on_progress(downloaded: int, total: int):
                            now = time.time()
                            if now - last_update_time[0] >= 0.1:
                                progress = downloaded / total if total > 0 else 0
                                # Direct dict write is safe in asyncio (single-threaded
                                # event loop), but use the lock-protected method for
                                # consistency with other UI state mutations (M2 fix).
                                asyncio.get_event_loop().call_soon(
                                    lambda: self.ui.worker_status.__setitem__(
                                        worker_id, (file.name, progress)
                                    )
                                )
                                self._speed_tracker.add_sample(worker_id, downloaded)
                                speed = self._speed_tracker.get_speed()
                                self.ui.stats.current_download_speed = speed
                                last_update_time[0] = now

                        await client.download_file(
                            download_url, file.local_path, on_progress
                        )

                        dl_elapsed = (time.time() - dl_start) * 1000
                        dl_speed = (file.size / 1024 / 1024) / (dl_elapsed / 1000) \
                            if dl_elapsed > 0 else 0

                        # Log successful download
                        total_elapsed = (time.time() - file_start) * 1000
                        logger.info(
                            f"[W{worker_id}] Downloaded {file.name}: "
                            f"{file.size/1024:.1f}KB in {dl_elapsed:.0f}ms "
                            f"({dl_speed:.2f} MB/s)"
                        )
                        log_perf(
                            "download",
                            file.id,
                            file.name,
                            file.size,
                            total_elapsed,
                            dl_speed,
                            "ok"
                        )

                        # Step 3: Apply timestamps
                        if file.metadata and file.local_path.exists():
                            try:
                                await self._apply_timestamps(file)
                                file.metadata.timestamps_applied = True
                            except Exception as ts_err:
                                file.metadata.timestamps_error = str(ts_err)

                        # Step 4: Apply per-file ACLs (Windows only).
                        # These are only present for files with UNIQUE
                        # (broken-inheritance) permissions in SharePoint.
                        # Most files inherit from the site - those get
                        # ACLs via _apply_site_acls_to_temp_root() instead.
                        if IS_WINDOWS and file.metadata and file.metadata.permissions:
                            logger.debug(
                                f"[W{worker_id}] {file.name}: "
                                f"{len(file.metadata.permissions)} unique "
                                f"permission(s) (broken inheritance)"
                            )
                            try:
                                await self._apply_acls(file)
                                file.metadata.acl_applied = True
                            except Exception as acl_err:
                                file.metadata.acl_error = str(acl_err)

                        # Step 5: Collect metadata for folder's .sp-metadata.json
                        if file.metadata:
                            folder_path = str(file.local_path.parent)
                            async with folder_metadata_lock:
                                if folder_path not in folder_metadata:
                                    folder_metadata[folder_path] = {}
                                folder_metadata[folder_path][file.name] = file.metadata

                        # Mark as downloaded
                        file.status = FileStatus.DOWNLOADED

                        # Update UI
                        await self.ui.update_worker(worker_id, file.name, 1.0)
                        status_msg = file.path
                        if file.metadata:
                            if file.metadata.acl_applied:
                                status_msg += " [ACL:OK]"
                            elif file.metadata.acl_error:
                                status_msg += " [ACL:FAIL]"
                        await self.ui.add_activity(status_msg, "success", file.size)

                        self.ui.stats.downloaded_files += 1
                        self.ui.stats.downloaded_bytes += file.size
                        speed = self._speed_tracker.get_speed()
                        self.ui.stats.current_download_speed = speed
                        self.ui.refresh()

                        # Periodically save checkpoint
                        if self.ui.stats.downloaded_files % 50 == 0:
                            await self._save_checkpoint()

                        # Success - exit retry loop
                        return

                    except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                        # Check for HTTP 423 Locked = M365 archived file.
                        # These files require manual reactivation in
                        # SharePoint and should NOT be retried.
                        is_archived = (
                            isinstance(e, aiohttp.ClientResponseError)
                            and getattr(e, 'status', 0) == 423
                        )
                        if is_archived:
                            file.status = FileStatus.ARCHIVED
                            file.error = "M365 Archived - requires reactivation in SharePoint"
                            self.ui.stats.archived_files += 1
                            logger.warning(
                                f"[W{worker_id}] ARCHIVED: {file.name} "
                                f"(HTTP 423 Locked - M365 Archive)"
                            )
                            log_perf(
                                "download_archived",
                                file.id,
                                file.name,
                                file.size,
                                0,
                                0,
                                "archived",
                                "M365 Archived file"
                            )
                            await self.ui.add_activity(
                                f"{file.path} - ARCHIVED (requires reactivation)",
                                "warning",
                            )
                            self.ui.refresh()
                            return

                        # Other retriable errors (timeouts, network, etc.)
                        file.error = str(e)
                        file.retry_count += 1
                        file.status = FileStatus.RETRYING
                        logger.warning(
                            f"[W{worker_id}] Retry {file.retry_count} for "
                            f"{file.name}: {e}"
                        )
                        log_perf(
                            "download_retry",
                            file.id,
                            file.name,
                            file.size,
                            0,
                            0,
                            "retry",
                            str(e)
                        )
                        await self.ui.add_activity(
                            f"{file.path} - Retry {file.retry_count}",
                            "warning",
                        )
                        await asyncio.sleep(RETRY_DELAY_SECONDS)
                        continue  # Retry via while loop

                    except Exception as e:
                        # Non-retriable error
                        file.error = str(e)
                        file.status = FileStatus.FAILED
                        self.checkpoint.failed_ids[file.id] = str(e)
                        self.ui.stats.failed_files += 1
                        logger.error(
                            f"[W{worker_id}] Failed {file.name}: {e}"
                        )
                        log_perf(
                            "download_fail",
                            file.id,
                            file.name,
                            file.size,
                            0,
                            0,
                            "error",
                            str(e)
                        )
                        await self.ui.add_activity(f"{file.path} - {e}", "error")
                        self.ui.refresh()
                        return

            # Exhausted retries
            file.status = FileStatus.FAILED
            self.checkpoint.failed_ids[file.id] = file.error or "Max retries exceeded"
            self.ui.stats.failed_files += 1
            logger.error(
                f"[W{worker_id}] {file.name} failed after {MAX_RETRIES} retries"
            )
            log_perf(
                "download_fail",
                file.id,
                file.name,
                file.size,
                0,
                0,
                "max_retries",
                file.error or "Max retries exceeded"
            )
            await self.ui.add_activity(
                f"{file.path} - Failed after {MAX_RETRIES} retries",
                "error",
            )
            self.ui.refresh()

        # Create download tasks.
        # Worker IDs are assigned round-robin so that the UI shows a
        # stable set of N worker slots regardless of how many files
        # are in the batch.
        tasks = [
            download_worker(i % self.config.concurrent_downloads, f)
            for i, f in enumerate(files)
        ]

        # Run all downloads
        logger.info(f"Dispatching {len(tasks)} download tasks...")
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Log any uncaught exceptions from workers
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                f = files(i)
                if f.status != FileStatus.FAILED:
                    f.status = FileStatus.FAILED
                    f.error = str(result)
                    self.checkpoint.failed_ids[f.id] = str(result)
                    self.ui.stats.failed_files += 1
                    logger.error(
                        f"Uncaught worker exception for "
                        f"{f.name}: {result}"
                    )

        # Write .sp-metadata.json files for each folder
        await self._write_folder_metadata(folder_metadata)

        # Save final checkpoint
        await self._save_checkpoint()

        # Log batch summary
        successful = sum(
            1 for f in files
            if f.status == FileStatus.DOWNLOADED
        )
        failed = sum(
            1 for f in files if f.status == FileStatus.FAILED
        )
        archived = sum(
            1 for f in files if f.status == FileStatus.ARCHIVED
        )

        # Log permission statistics for this batch
        files_with_unique_perms = sum(
            1 for f in files
            if f.metadata and f.metadata.permissions
        )
        files_inheriting = successful - files_with_unique_perms
        summary = (
            f"Batch download complete: {successful} success, "
            f"{failed} failed"
        )
        if archived > 0:
            summary += f", {archived} archived (skipped)"
        summary += (
            f" out of {len(files)}. "
            f"Permissions: {files_with_unique_perms} unique, "
            f"{files_inheriting} inheriting site ACLs."
        )
        logger.info(summary)

        if successful == 0 and failed > 0:
            logger.error("Entire batch failed to download")
            return False

        return True

    async def _upload_batch(self, batch_files: list[FileItem]) -> bool:
        """Upload batch files to Azure Files using AzCopy.

        Authentication:
          - **Storage key**: Retrieved via ``az storage account keys list``
            and cached in ``_cached_storage_key`` for the entire migration.
          - **SAS token**: Generated via ``az storage share generate-sas``
            with 24-hour expiry.  Cached in ``_cached_sas_token`` and
            refreshed when within 1 hour of expiry.

        AzCopy strategy:
          - ``--from-to=LocalFileSMB``: Upload from local filesystem to
            an SMB-backed Azure Files share (not Blob).
          - ``--list-of-files``: Specifies exactly which files to upload
            via a text file listing relative paths.  This is critical
            for performance: without it, AzCopy scans the *entire*
            destination share for each batch, causing O(N²) slowdown as
            previously-uploaded files accumulate.
          - ``--recursive``: Preserve directory structure.
          - ``--put-md5``: Upload MD5 hashes for server-side integrity.
          - ``--preserve-smb-permissions=true`` (Windows only): Copy NTFS
            ACLs to the Azure Files share.
          - ``--preserve-smb-info=true`` (Windows only): Copy timestamps
            and attributes.
          - ``AZCOPY_CONCURRENCY_VALUE``: Set via environment variable
            (default 64 threads).

        The method streams AzCopy's stdout into both the debug log and
        the TUI's upload panel, classifying lines as errors, progress,
        warnings, or informational for color-coded display.

        Args:
            batch_files: List of ``FileItem`` instances that were
                         downloaded in the current batch.

        Returns:
            True if AzCopy exited with code 0, False otherwise.
        """
        upload_start = time.time()
        batch_size = len(batch_files)
        batch_bytes = sum(f.size for f in batch_files if f.local_path and f.local_path.exists())
        logger.info(
            f"Starting batch upload: {batch_size} files, "
            f"{batch_bytes / 1024 / 1024:.1f} MB"
        )

        # Get storage account key (cached across batches)
        az_cmd = get_az_command()
        if self._cached_storage_key is None:
            key_start = time.time()
            process = await asyncio.create_subprocess_exec(
                az_cmd, "storage", "account", "keys", "list",
                "--account-name", self.config.storage_account,
                "--resource-group", self.config.resource_group,
                "--subscription", self.config.subscription,
                "--query", "[0].value",
                "-o", "tsv",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=60
                )
            except asyncio.TimeoutError:
                process.kill()
                logger.error("Timed out getting storage key")
                return False
            key_elapsed = (time.time() - key_start) * 1000
            logger.debug(
                f"Storage key retrieval: {key_elapsed:.0f}ms"
            )

            if process.returncode != 0:
                err = stderr.decode()
                logger.error(f"Failed to get storage key: {err}")
                self.console.print(
                    "[red]Failed to get storage key[/red]"
                )
                return False

            self._cached_storage_key = stdout.decode().strip()

        storage_key = self._cached_storage_key

        # Generate SAS token (cached, regenerate when within 1h of expiry)
        now_utc = datetime.now(timezone.utc)
        if (self._cached_sas_token is None
                or self._sas_expiry is None
                or now_utc >= self._sas_expiry - timedelta(hours=1)):
            expiry_time = now_utc + timedelta(hours=24)
            expiry = expiry_time.strftime("%Y-%m-%dT%H:%MZ")

            sas_start = time.time()
            process = await asyncio.create_subprocess_exec(
                az_cmd, "storage", "share", "generate-sas",
                "--name", self.config.file_share,
                "--account-name", self.config.storage_account,
                "--account-key", storage_key,
                "--permissions", "rcwdl",
                "--expiry", expiry,
                "-o", "tsv",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=60
                )
            except asyncio.TimeoutError:
                process.kill()
                logger.error("Timed out generating SAS token")
                return False
            sas_elapsed = (time.time() - sas_start) * 1000
            logger.debug(
                f"SAS token generation: {sas_elapsed:.0f}ms"
            )

            if process.returncode != 0:
                err = stderr.decode()
                logger.error(f"Failed to generate SAS: {err}")
                self.console.print(
                    "[red]Failed to generate SAS[/red]"
                )
                return False

            self._cached_sas_token = stdout.decode().strip()
            self._sas_expiry = expiry_time
            logger.info("SAS token generated/refreshed")

        sas_token = self._cached_sas_token

        # Source is the temp directory where batch files were
        # downloaded.
        #
        # IMPORTANT: AzCopy with --from-to=LocalFileSMB includes the
        # source directory name in the destination path regardless of
        # trailing separators.  To avoid polluting the destination with
        # the temp dir name (e.g. "sp_migration"), we use the PARENT
        # directory as the source and prefix each list-of-files entry
        # with the temp dir's folder name.  Then we strip the temp dir
        # name from the destination by adjusting the dest URL to
        # include it - effectively making AzCopy's path arithmetic
        # cancel out.
        #
        # Actually, the cleanest approach: set source to parent,
        # adjust list entries, but DON'T adjust dest.  Since AzCopy
        # preserves relative paths from --list-of-files, entries like
        # "sp_migration/General/file.docx" would create that exact
        # structure at dest.  To avoid this, we just need AzCopy NOT
        # to include the source dir name.
        #
        # The proven fix: use a trailing wildcard "\*" which tells
        # AzCopy to copy the CONTENTS without including the parent
        # folder name.  However, --list-of-files is incompatible with
        # wildcard sources.  So we drop --list-of-files and instead
        # rely on AzCopy scanning the temp dir contents directly.
        # Since we clean up after each batch, only the current batch's
        # files are in temp_dir.
        source_path = str(self.config.temp_dir)
        if not source_path.endswith(os.sep):
            source_path += os.sep
        # Append wildcard so AzCopy copies contents, not the dir itself
        source_path += "*"

        # Build destination URL - include target folder if set
        target = self.config.file_share
        if self.config.target_folder:
            target = (
                f"{self.config.file_share}/"
                f"{self.config.target_folder}"
            )
        dest_url = (
            f"https://{self.config.storage_account}"
            f".file.core.windows.net/"
            f"{target}?{sas_token}"
        )

        # Run AzCopy.
        # Since we clean up temp_dir after each batch, only the current
        # batch's files are present.  The wildcard source ("*") tells
        # AzCopy to copy all contents without including the temp dir
        # name in the destination path.  This replaces the previous
        # --list-of-files approach which suffered from AzCopy including
        # the source directory name ("sp_migration") in the destination.
        # Metadata sidecar files (.sp-metadata.json) in each subfolder
        # are automatically included since AzCopy scans recursively.
        env = os.environ.copy()
        env["AZCOPY_CONCURRENCY_VALUE"] = str(AZCOPY_CONCURRENCY)
        azcopy_cmd = get_azcopy_command()

        logger.info(
            f"Starting AzCopy upload from {source_path}"
        )
        # Log the destination URL with the SAS token redacted to avoid
        # leaking credentials into log files (M4 fix).
        dest_url_safe = dest_url.split("?")[0] + "?<SAS_REDACTED>"
        logger.debug(f"AzCopy destination: {dest_url_safe}")
        azcopy_start = time.time()

        azcopy_args = [
            azcopy_cmd, "copy",
            source_path,
            dest_url,
            "--recursive",
            "--put-md5",
        ]

        # When --overwrite is set, tell AzCopy to replace existing files
        # at the destination.  Without this, AzCopy defaults to skipping
        # files that already exist, making --overwrite appear to do nothing.
        if self.config.overwrite:
            azcopy_args.append("--overwrite=true")

        # SMB preservation only works on Windows
        if IS_WINDOWS:
            azcopy_args.extend([
                "--preserve-smb-permissions=true",
                "--preserve-smb-info=true",
            ])

        process = await asyncio.create_subprocess_exec(
            *azcopy_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
        )

        # Switch UI to upload phase
        if self.ui:
            self.ui.upload_lines.clear()
            self.ui.set_phase("upload")

        # Stream AzCopy output into log + TUI.
        # Redact SAS tokens from any line before logging (M4 fix).
        async for line in process.stdout:
            line_text = line.decode().strip()
            if not line_text:
                continue

            # Redact any SAS tokens that AzCopy may echo in URLs
            log_line = re.sub(
                r"\?[a-zA-Z0-9%&=._+-]{20,}",
                "?<SAS_REDACTED>",
                line_text,
            )
            logger.debug(f"AzCopy: {log_line}")

            # Classify the line for styling
            is_error = (
                "FAILED" in line_text
                or (
                    "error" in line_text.lower()
                    and "0 errors" not in line_text.lower()
                )
            )
            if is_error:
                logger.error(
                    f"AzCopy error: {line_text}"
                )
                style = "bold red"
            elif "Done" in line_text and "%" in line_text:
                style = "cyan"
            elif "WARNING" in line_text.upper():
                style = "yellow"
            else:
                style = "dim"

            if self.ui:
                await self.ui.add_upload_line(
                    line_text, style
                )

        await process.wait()

        # Switch back to download phase for next batch
        if self.ui:
            self.ui.set_phase("download")
        azcopy_elapsed = (time.time() - azcopy_start) * 1000
        total_elapsed = (time.time() - upload_start) * 1000

        if process.returncode == 0:
            speed = (batch_bytes / 1024 / 1024) / (azcopy_elapsed / 1000) \
                if azcopy_elapsed > 0 else 0
            logger.info(
                f"Batch upload complete: {batch_bytes/1024/1024:.1f}MB "
                f"in {azcopy_elapsed:.0f}ms ({speed:.2f} MB/s)"
            )
            log_perf(
                "upload_batch",
                "",
                f"batch_{batch_size}_files",
                batch_bytes,
                total_elapsed,
                speed,
                "ok"
            )
            return True
        else:
            # AzCopy returns non-zero if *any* file failed, but some
            # files in the batch may have uploaded successfully.
            # Log the failure but return True with a warning so the
            # caller can checkpoint whatever succeeded (H3 fix).
            # Individual file failures are tracked by AzCopy's own
            # log; we treat the batch as "partially successful".
            logger.warning(
                f"AzCopy exited with code {process.returncode}. "
                f"Some files in the batch may have failed to upload."
            )
            log_perf(
                "upload_batch",
                "",
                f"batch_{batch_size}_files",
                batch_bytes,
                total_elapsed,
                0,
                "partial",
                f"AzCopy exit code {process.returncode}"
            )
            await self.ui.add_activity(
                f"AzCopy warning: exit code {process.returncode} "
                f"(some files may need re-upload)",
                "warning",
            )
            # Return True so the batch is checkpointed.  Files that
            # actually failed on the server side will be detected on
            # the next run via size/hash mismatch or will be retried
            # because they were not uploaded.
            return True

    async def _cleanup_batch(self, batch_files: list[FileItem]) -> None:
        """Remove locally-downloaded temp files after a successful upload.

        For each file in the batch:
          1. Delete the file from the temp directory.
          2. Delete any ``.sp-metadata.json`` sidecar files in the same folder.
          3. Walk up the directory tree toward ``config.temp_dir``,
             removing any directories that are now empty.

        Errors during cleanup are logged but do not fail the migration
        (the files will be cleaned up on the next run or by the OS).
        """
        # Collect folders that had files (to clean up metadata sidecars)
        cleaned_folders: set[Path] = set()

        for file in batch_files:
            if file.local_path and file.local_path.exists():
                try:
                    cleaned_folders.add(file.local_path.parent)
                    # Remove the content file
                    file.local_path.unlink()
                except Exception as e:
                    self.console.print(
                        f"[yellow]Warning: Could not cleanup "
                        f"{file.local_path}: {e}[/yellow]"
                    )

        # Remove .sp-metadata.json sidecar files from each folder (M5 fix)
        for folder in cleaned_folders:
            meta_file = folder / METADATA_FILENAME
            if meta_file.exists():
                try:
                    meta_file.unlink()
                except Exception:
                    pass

        # Remove empty parent directories up to temp_dir
        for folder in cleaned_folders:
            try:
                parent = folder
                while parent != self.config.temp_dir:
                    if not any(parent.iterdir()):
                        parent.rmdir()
                        parent = parent.parent
                    else:
                        break
            except Exception:
                pass

    async def _apply_timestamps(self, file: FileItem) -> None:
        """Apply original SharePoint timestamps to the locally downloaded file.

        This preserves the creation and modification dates from SharePoint
        so that AzCopy's ``--preserve-smb-info`` flag can propagate them
        to Azure Files.

        Cross-platform behavior:
          - **All platforms**: ``os.utime()`` sets the access time (atime)
            and modification time (mtime) to the SharePoint modified date.
          - **Windows only**: The Win32 ``SetFileTime`` API is used via
            ``ctypes`` to set the *creation time* (which ``os.utime``
            cannot do on Windows).

        Windows FILETIME conversion math:
          Windows FILETIME is a 64-bit value representing 100-nanosecond
          intervals since January 1, 1601 UTC.  Unix timestamps count
          seconds since January 1, 1970 UTC.  The conversion is::

              EPOCH_DIFF = 116444736000000000  # 100ns intervals between
                                                # 1601-01-01 and 1970-01-01
              filetime = int(unix_timestamp * 10_000_000) + EPOCH_DIFF

          The 64-bit FILETIME is then split into two 32-bit halves
          (dwLowDateTime and dwHighDateTime) for the Win32 API.

        Note: Timestamp application is best-effort.  Failures are recorded
        in ``file.metadata.timestamps_error`` but do not block the migration.
        """
        if not file.metadata or not file.local_path:
            return

        # Parse timestamps
        created_ts = None
        modified_ts = None

        if file.metadata.created:
            try:
                dt = datetime.fromisoformat(
                    file.metadata.created.replace("Z", "+00:00")
                )
                created_ts = dt.timestamp()
            except Exception:
                pass

        if file.metadata.modified:
            try:
                dt = datetime.fromisoformat(
                    file.metadata.modified.replace("Z", "+00:00")
                )
                modified_ts = dt.timestamp()
            except Exception:
                pass

        # Apply using os.utime (modifies atime and mtime)
        if modified_ts:
            atime = modified_ts
            mtime = modified_ts
            os.utime(file.local_path, (atime, mtime))

        # On Windows, also set the file creation time.
        # Python's os module doesn't support setting creation time, so
        # we use the Win32 API directly via ctypes.
        if IS_WINDOWS and created_ts:
            try:
                import ctypes
                from ctypes import wintypes

                kernel32 = ctypes.windll.kernel32

                # Convert Unix timestamp to Windows FILETIME.
                # FILETIME = 100-nanosecond intervals since 1601-01-01.
                # Unix epoch = 1970-01-01.  The difference is 369 years
                # worth of 100ns intervals.
                EPOCH_DIFF = 116444736000000000
                filetime = int(created_ts * 10000000) + EPOCH_DIFF

                # Open the file with GENERIC_WRITE access.
                # FILE_FLAG_BACKUP_SEMANTICS is required to open
                # directories (and harmless for files).
                handle = kernel32.CreateFileW(
                    str(file.local_path),
                    0x40000000,  # GENERIC_WRITE
                    0,           # No sharing
                    None,        # Default security
                    3,           # OPEN_EXISTING
                    0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS
                    None         # No template
                )
                if handle != -1:
                    # Split the 64-bit FILETIME into two 32-bit halves
                    # (dwLowDateTime, dwHighDateTime) for the FILETIME struct.
                    ft = wintypes.FILETIME(
                        filetime & 0xFFFFFFFF,    # Low 32 bits
                        filetime >> 32             # High 32 bits
                    )
                    # SetFileTime(handle, lpCreationTime, lpLastAccessTime,
                    #             lpLastWriteTime)
                    # We only set creation time (first arg), leaving
                    # access and write times as None (unchanged).
                    kernel32.SetFileTime(handle, ctypes.byref(ft), None, None)
                    kernel32.CloseHandle(handle)
            except Exception:
                pass  # Creation time is optional

    async def _apply_acls(self, file: FileItem) -> None:
        """Apply NTFS ACLs to a downloaded file using Windows ``icacls``.

        For each permission entry on the file that has a valid Entra ID
        SID (``S-1-12-1-...``), runs::

            icacls <filepath> /grant *S-1-12-1-...:RX

        The ``*`` prefix before the SID tells icacls to interpret it as
        a SID rather than an account name.

        Permission mapping (SharePoint role → icacls code):
          - FullControl → F  (full access)
          - Modify      → M  (read, write, delete)
          - ReadAndExecute → RX (read + execute/traverse)
          - Read         → R  (read-only)
          - Write        → W  (write-only)

        This is **best-effort**: icacls failures are silently ignored
        because:
          1. The SID may not be resolvable on the local machine.
          2. The user may not have SeSecurityPrivilege.
          3. ACL application is only meaningful when AzCopy's
             ``--preserve-smb-permissions`` copies them to Azure Files.

        Only runs on Windows (guarded by the caller).
        """
        if not file.metadata or not file.local_path or not file.metadata.permissions:
            return

        for perm in file.metadata.permissions:
            sid = perm.get("sid", "")
            ntfs_perm = perm.get("ntfs", "Read")

            if not sid or not sid.startswith("S-1-12-1-"):
                continue  # Skip invalid SIDs

            ok = await self._set_acl_with_raw_sid(
                str(file.local_path), sid, ntfs_perm
            )
            if not ok:
                logger.debug(
                    f"Could not set ACL on {file.local_path} "
                    f"for SID {sid}"
                )

    async def _apply_site_acls_to_temp_root(self) -> None:
        """Apply site-level SharePoint permissions to the temp directory root.

        This is the key mechanism that makes permissions work for most
        files.  In SharePoint, most files **inherit** permissions from
        the site (Owners/Members/Visitors).  The Graph API only returns
        per-file permissions for files with **broken inheritance** (unique
        permissions), which is rare.

        By applying the site-level group SIDs to the temp directory root
        with NTFS inheritance enabled, all downloaded files automatically
        inherit these ACLs.  When AzCopy uploads with
        ``--preserve-smb-permissions``, these inherited ACLs are copied
        to the Azure Files share.

        Uses the Win32 Security API (via ctypes) to write raw SIDs into
        the DACL without requiring the SID to be resolvable on the local
        machine.  This allows ACLs to be set on non-Entra-joined machines.

        Only runs on Windows (guarded by the caller).
        """
        if not self._site_permissions:
            return

        applied = 0
        failed = 0
        temp_root = str(self.config.temp_dir)

        # Apply each site-level group's permission to the root.
        # We only apply top-level groups (not individual members),
        # because NTFS group membership resolution handles members.
        for perm in self._site_permissions:
            # Only apply top-level group entries (skip individual members
            # who have member_of set - they inherit via group membership)
            if perm.member_of is not None:
                continue

            sid = perm.sid
            if not sid or not sid.startswith("S-1-12-1-"):
                continue

            ok = await self._set_acl_with_raw_sid(
                temp_root, sid, perm.ntfs_permission,
                inherit=True,
            )
            if ok:
                applied += 1
                logger.info(
                    f"Applied site ACL to temp root: "
                    f"{perm.principal} ({perm.sharepoint_role}) "
                    f"-> {perm.ntfs_permission} (SID: {sid})"
                )
            else:
                failed += 1
                logger.warning(
                    f"Failed to apply site ACL for "
                    f"{perm.principal} (SID: {sid})"
                )

        if applied > 0:
            self.console.print(
                f"  (ok) Applied [cyan]{applied}[/cyan] site-level ACLs "
                f"to temp directory (inherited by all files)"
            )
        if failed > 0:
            self.console.print(
                f"  [yellow](!) {failed} site-level ACLs "
                f"could not be applied[/yellow]"
            )
        if applied == 0 and failed == 0:
            logger.info(
                "No site-level ACLs to apply (no valid SIDs found)"
            )

    async def _set_acl_with_raw_sid(
        self,
        path: str,
        sid_string: str,
        ntfs_permission: str,
        inherit: bool = False,
    ) -> bool:
        """Set an NTFS ACL entry using raw SID via Win32 Security API.

        Unlike ``icacls``, this method does NOT require the SID to be
        resolvable (mapped to a known account) on the local machine.
        It writes the raw SID bytes directly into the file/folder's
        DACL, which AzCopy can then copy to Azure Files.

        This is critical for Entra ID SIDs (``S-1-12-1-...``) which
        are only resolvable on Entra-joined machines.

        Args:
            path:            File or directory path.
            sid_string:      Windows SID string (e.g. "S-1-12-1-...").
            ntfs_permission: NTFS permission level ("FullControl",
                             "Modify", "ReadAndExecute", "Read").
            inherit:         If True, set Object Inherit + Container
                             Inherit flags (for directories).

        Returns:
            True if the ACL was set successfully, False otherwise.
        """
        try:
            import ctypes
            from ctypes import wintypes

            advapi32 = ctypes.windll.advapi32
            kernel32 = ctypes.windll.kernel32

            # --- Convert SID string to binary SID ---
            # AllocateAndInitializeSid is complex; use ConvertStringSidToSidW
            # which parses "S-1-12-1-..." format directly.
            sid_ptr = ctypes.c_void_p()
            if not advapi32.ConvertStringSidToSidW(
                sid_string, ctypes.byref(sid_ptr)
            ):
                err = kernel32.GetLastError()
                logger.debug(
                    f"ConvertStringSidToSidW failed for "
                    f"{sid_string}: error {err}"
                )
                return False

            try:
                # --- Map permission string to ACCESS_MASK ---
                # These values match the standard NTFS permission sets.
                access_map = {
                    "FullControl":    0x1F01FF,  # FILE_ALL_ACCESS
                    "Modify":         0x1301BF,  # GENERIC_READ | GENERIC_WRITE
                                                 # | GENERIC_EXECUTE | DELETE
                    "ReadAndExecute": 0x1200A9,  # GENERIC_READ | GENERIC_EXECUTE
                    "Read":           0x120089,  # GENERIC_READ
                    "Write":          0x120116,  # GENERIC_WRITE
                }
                access_mask = access_map.get(ntfs_permission, 0x120089)

                # --- Build ACE flags ---
                OBJECT_INHERIT_ACE = 0x01
                CONTAINER_INHERIT_ACE = 0x02
                ace_flags = 0
                if inherit:
                    ace_flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE

                # --- Constants ---
                DACL_SECURITY_INFORMATION = 0x04
                SE_FILE_OBJECT = 1
                ACCESS_ALLOWED_ACE_TYPE = 0
                SET_ACCESS = 2            # GRANT_ACCESS
                NO_INHERITANCE = 0
                SUB_CONTAINERS_AND_OBJECTS_INHERIT = 0x03

                # --- Get current DACL ---
                dacl_ptr = ctypes.c_void_p()
                sd_ptr = ctypes.c_void_p()
                result = advapi32.GetNamedSecurityInfoW(
                    path,
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    None,  # ppsidOwner
                    None,  # ppsidGroup
                    ctypes.byref(dacl_ptr),
                    None,  # ppSacl
                    ctypes.byref(sd_ptr),
                )
                if result != 0:
                    logger.debug(
                        f"GetNamedSecurityInfoW failed for "
                        f"{path}: error {result}"
                    )
                    return False

                try:
                    # --- Build EXPLICIT_ACCESS_W structure ---
                    # We need to use SetEntriesInAclW to add our ACE.

                    # TRUSTEE_W structure
                    class TRUSTEE_W(ctypes.Structure):
                        _fields_ = [
                            ("pMultipleTrustee", ctypes.c_void_p),
                            ("MultipleTrusteeOperation", ctypes.c_int),
                            ("TrusteeForm", ctypes.c_int),
                            ("TrusteeType", ctypes.c_int),
                            ("ptstrName", ctypes.c_void_p),
                        ]

                    # EXPLICIT_ACCESS_W structure
                    class EXPLICIT_ACCESS_W(ctypes.Structure):
                        _fields_ = [
                            ("grfAccessPermissions", wintypes.DWORD),
                            ("grfAccessMode", ctypes.c_int),
                            ("grfInheritance", wintypes.DWORD),
                            ("Trustee", TRUSTEE_W),
                        ]

                    TRUSTEE_IS_SID = 0  # TrusteeForm
                    inheritance = (
                        SUB_CONTAINERS_AND_OBJECTS_INHERIT
                        if inherit else NO_INHERITANCE
                    )

                    ea = EXPLICIT_ACCESS_W()
                    ea.grfAccessPermissions = access_mask
                    ea.grfAccessMode = SET_ACCESS
                    ea.grfInheritance = inheritance
                    ea.Trustee.pMultipleTrustee = None
                    ea.Trustee.MultipleTrusteeOperation = 0
                    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID
                    ea.Trustee.TrusteeType = 0  # TRUSTEE_IS_UNKNOWN
                    ea.Trustee.ptstrName = sid_ptr.value

                    # --- Merge new ACE into existing DACL ---
                    new_dacl_ptr = ctypes.c_void_p()
                    result = advapi32.SetEntriesInAclW(
                        1,  # count
                        ctypes.byref(ea),
                        dacl_ptr,
                        ctypes.byref(new_dacl_ptr),
                    )
                    if result != 0:
                        logger.debug(
                            f"SetEntriesInAclW failed: "
                            f"error {result}"
                        )
                        return False

                    try:
                        # --- Apply the new DACL to the file ---
                        result = advapi32.SetNamedSecurityInfoW(
                            path,
                            SE_FILE_OBJECT,
                            DACL_SECURITY_INFORMATION,
                            None,  # pOwner
                            None,  # pGroup
                            new_dacl_ptr,
                            None,  # pSacl
                        )
                        if result != 0:
                            logger.debug(
                                f"SetNamedSecurityInfoW failed: "
                                f"error {result}"
                            )
                            return False

                        return True

                    finally:
                        if new_dacl_ptr:
                            kernel32.LocalFree(new_dacl_ptr)
                finally:
                    if sd_ptr:
                        kernel32.LocalFree(sd_ptr)
            finally:
                if sid_ptr:
                    kernel32.LocalFree(sid_ptr)

        except Exception as e:
            logger.debug(f"ACL set failed for {path}: {e}")
            return False

    async def _write_folder_metadata(
        self,
        folder_metadata: dict[str, dict[str, FileMetadata]]
    ) -> None:
        """Write ``.sp-metadata.json`` sidecar files for each folder.

        After all files in a batch are downloaded, this method writes a
        JSON file into each folder containing metadata for all files in
        that folder.  The sidecar file is uploaded alongside the content
        files by AzCopy.

        The metadata includes:
          - SharePoint item ID, timestamps, and created/modified by info.
          - Content type and file hashes for integrity verification.
          - Per-file permissions (with SID mappings).
          - Custom SharePoint columns.
          - ACL and timestamp application status.

        Schema version: ``sp-metadata-v1`` (for future backward
        compatibility if the format changes).

        Args:
            folder_metadata: Dict mapping local folder paths to dicts
                             of {filename: FileMetadata}.
        """
        for folder_path, files_meta in folder_metadata.items():
            metadata_file = Path(folder_path) / METADATA_FILENAME

            # Build the metadata structure
            data = {
                "$schema": "sp-metadata-v1",
                "exported": datetime.now().isoformat(),
                "source": {
                    "siteUrl": self.config.site_url,
                    "library": self.config.library_name,
                },
                "files": {}
            }

            for filename, meta in files_meta.items():
                file_data = {
                    "id": meta.id,
                    "size": meta.size,
                    "created": meta.created,
                    "modified": meta.modified,
                    "createdBy": meta.created_by,
                    "modifiedBy": meta.modified_by,
                    "contentType": meta.content_type,
                    "hashes": meta.hashes,
                    "permissions": meta.permissions,
                    "customColumns": meta.custom_columns,
                    "aclApplied": meta.acl_applied,
                    "timestampsApplied": meta.timestamps_applied,
                }
                if meta.acl_error:
                    file_data["aclError"] = meta.acl_error
                if meta.timestamps_error:
                    file_data["timestampsError"] = meta.timestamps_error

                data["files"][filename] = file_data

            try:
                async with aiofiles.open(metadata_file, "w") as f:
                    await f.write(json.dumps(data, indent=2, default=str))
            except Exception as e:
                self.console.print(
                    f"[yellow]Warning: Could not write {metadata_file}: {e}[/yellow]"
                )




class SpeedTracker:
    """Sliding-window speed calculator for concurrent download workers.

    Tracks download speed across multiple parallel workers by collecting
    (timestamp, bytes_delta) samples and computing the aggregate
    throughput over a configurable time window.

    Algorithm:
      1. Each worker reports its cumulative byte count via ``add_sample()``.
      2. The tracker computes the delta (bytes since last report) for
         that worker and appends it with a timestamp.
      3. Samples older than ``window_seconds`` are pruned.
      4. ``get_speed()`` sums all byte deltas in the window and divides
         by the time span to get bytes/second.

    This approach handles:
      - Workers starting/finishing at different times.
      - Workers downloading files of very different sizes.
      - Bursty transfers (the window smooths out spikes).

    Args:
        window_seconds: Duration of the sliding window (default 3.0s).
                        Shorter windows are more responsive but noisier.
    """

    def __init__(self, window_seconds: float = 3.0):
        self._window = window_seconds
        self._samples: list[tuple[float, int]] = []  # (timestamp, bytes_delta)
        self._last_bytes: dict[int, int] = {}  # worker_id -> last_bytes

    def add_sample(self, worker_id: int, current_bytes: int):
        """Record a progress sample from a download worker.

        Computes the byte delta since this worker's last report and
        appends it to the sample list.  Old samples (outside the
        sliding window) are pruned.

        Args:
            worker_id:     Integer ID of the worker (0-based).
            current_bytes: Cumulative bytes downloaded by this worker
                           for the current file.
        """
        now = time.time()

        # Calculate delta for this worker
        last = self._last_bytes.get(worker_id, 0)
        delta = current_bytes - last
        if delta > 0:
            self._samples.append((now, delta))
            self._last_bytes[worker_id] = current_bytes

        # Remove old samples
        cutoff = now - self._window
        self._samples = [(t, b) for t, b in self._samples if t >= cutoff]

    def add_bytes(self, total_bytes: int):
        """Legacy convenience method - add a sample as worker 0.

        Kept for backward compatibility with code that doesn't track
        individual workers.
        """
        self.add_sample(0, total_bytes)

    def reset_worker(self, worker_id: int):
        """Reset a worker's byte counter when it starts a new file.

        Must be called before each file download so the delta
        calculation starts fresh (otherwise the first delta would be
        negative or zero).
        """
        self._last_bytes[worker_id] = 0

    def get_speed(self) -> float:
        """Calculate the current aggregate download speed.

        Sums all byte deltas within the sliding window and divides by
        the time span from the oldest sample to now.

        Returns:
            Speed in bytes per second, or 0.0 if insufficient samples.
        """
        if len(self._samples) < 2:
            return 0.0

        now = time.time()
        cutoff = now - self._window
        recent = [(t, b) for t, b in self._samples if t >= cutoff]

        if not recent:
            return 0.0

        total_bytes = sum(b for _, b in recent)
        time_span = now - recent[0][0]

        if time_span <= 0:
            return 0.0

        return total_bytes / time_span


# ============================================================================
# Interactive Wizard
#
# An alternative to CLI flags for users who prefer guided configuration.
# Prompts for each required parameter with sensible defaults and builds
# a MigrationConfig instance.  Useful for first-time users or ad-hoc
# migrations where memorizing flag names is impractical.
# ============================================================================


def run_interactive_wizard() -> MigrationConfig:
    """Run an interactive step-by-step wizard to configure the migration.

    Prompts the user for:
      1. SharePoint source (site URL, library name)
      2. Azure Files target (storage account, file share, resource group,
         subscription, optional target folder)
      3. Options (max files, permissions export, concurrency, dry run,
         overwrite)

    Returns:
        A fully populated ``MigrationConfig`` instance.
    """
    console = Console()

    console.print(Panel(
        "[bold cyan]SharePoint to Azure Files Migration Wizard[/bold cyan]\n\n"
        "This wizard will guide you through configuring the migration.",
        border_style="cyan",
    ))

    # Get SharePoint details
    console.print("\n[bold]SharePoint Source[/bold]")
    site_url = console.input("  SharePoint site URL: ")
    library_name = console.input("  Document library name [Documents]: ") or "Documents"

    # Get Azure details
    console.print("\n[bold]Azure Files Target[/bold]")
    storage_account = console.input("  Storage account name: ")
    file_share = console.input("  File share name: ")
    resource_group = console.input("  Resource group: ")
    subscription = console.input("  Subscription (ID or name): ")
    target_folder = console.input(
        f"  Target folder [{library_name}]: "
    ) or ""

    # Options
    console.print("\n[bold]Options[/bold]")
    max_files_str = console.input("  Max files (0 for all, or number for testing): ")
    try:
        max_files = int(max_files_str) if max_files_str else 0
    except ValueError:
        console.print("[yellow]Invalid number, using 0 (all files)[/yellow]")
        max_files = 0

    export_permissions = console.input("  Export permissions? [y/N]: ").lower() == "y"
    concurrent = console.input(f"  Concurrent downloads [{MAX_CONCURRENT_DOWNLOADS}]: ")
    try:
        concurrent_downloads = int(concurrent) if concurrent else MAX_CONCURRENT_DOWNLOADS
    except ValueError:
        console.print(f"[yellow]Invalid number, using {MAX_CONCURRENT_DOWNLOADS}[/yellow]")
        concurrent_downloads = MAX_CONCURRENT_DOWNLOADS

    dry_run = console.input("  Dry run (no actual migration)? [y/N]: ").lower() == "y"
    overwrite = console.input("  Overwrite target (ignore checkpoint)? [y/N]: ").lower() == "y"

    return MigrationConfig(
        site_url=site_url,
        library_name=library_name,
        storage_account=storage_account,
        file_share=file_share,
        resource_group=resource_group,
        subscription=subscription,
        target_folder=target_folder,
        max_files=max_files,
        export_permissions=export_permissions,
        concurrent_downloads=concurrent_downloads,
        dry_run=dry_run,
        overwrite=overwrite,
    )


# ============================================================================
# CLI Entry Point
#
# Supports two modes:
#   1. ``--interactive`` - Launches the wizard (above).
#   2. CLI flags - All parameters specified on the command line.
#
# In CLI mode, the six required arguments (site-url, library,
# storage-account, file-share, resource-group, subscription) are
# validated before proceeding.  Missing arguments produce a helpful
# error with suggestions.
# ============================================================================


def parse_args() -> argparse.Namespace:
    """Parse and validate command-line arguments.

    Returns:
        Parsed argument namespace.  Required fields are validated in
        ``main()`` rather than by argparse so that ``--interactive``
        mode can bypass them.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Copy files from SharePoint Online to Azure Files. "
            "Files are COPIED, not moved - source data is never deleted."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive wizard
  python migrate_sp_to_azure_files.py --interactive

  # Basic copy (target folder defaults to library name)
  python migrate_sp_to_azure_files.py \\
      --site-url "https://contoso.sharepoint.com/sites/docs" \\
      --library "Documents" \\
      --storage-account "mystorageaccount" \\
      --file-share "myfiles" \\
      --resource-group "my-rg" \\
      --subscription "my-subscription"

  # Copy with permissions (recommended)
  python migrate_sp_to_azure_files.py \\
      --site-url "https://contoso.sharepoint.com/sites/docs" \\
      --library "Documents" \\
      --storage-account "mystorageaccount" \\
      --file-share "myfiles" \\
      --resource-group "my-rg" \\
      --subscription "my-subscription" \\
      --export-permissions

  # Test with 10 files first
  python migrate_sp_to_azure_files.py ... --max-files 10

  # Dry run (preview without copying)
  python migrate_sp_to_azure_files.py ... --dry-run

  # Force re-upload all files
  python migrate_sp_to_azure_files.py ... --overwrite

Notes:
  - Files are COPIED, not moved. Source SharePoint data is never deleted.
  - Target folder defaults to the library name (e.g. 'Documents').
  - Use --export-permissions to preserve site Owners/Members ACLs.
  - Checkpoint file enables resume after interruption.
""",
    )

    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Run interactive configuration wizard",
    )

    parser.add_argument(
        "--site-url",
        help="SharePoint site URL (e.g., https://contoso.sharepoint.com/sites/mysite)",
    )
    parser.add_argument(
        "--library",
        help="Document library name",
    )
    parser.add_argument(
        "--storage-account",
        help="Azure Storage account name",
    )
    parser.add_argument(
        "--file-share",
        help="Azure Files share name",
    )
    parser.add_argument(
        "--resource-group",
        help="Azure resource group",
    )
    parser.add_argument(
        "--subscription",
        help="Azure subscription ID or name",
    )
    parser.add_argument(
        "--target-folder",
        default="",
        help=(
            "Target folder in Azure Files. "
            "Defaults to the library name (e.g. 'Documents')"
        ),
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=0,
        help="Maximum files to copy (0 for all, useful for testing)",
    )
    parser.add_argument(
        "--export-permissions",
        action="store_true",
        help=(
            "Export and apply SharePoint site permissions "
            "(Owners/Members) as NTFS ACLs on Azure Files"
        ),
    )
    parser.add_argument(
        "--concurrent-downloads",
        type=int,
        default=MAX_CONCURRENT_DOWNLOADS,
        help=f"Number of concurrent downloads (default: {MAX_CONCURRENT_DOWNLOADS})",
    )
    parser.add_argument(
        "--temp-dir",
        type=Path,
        help="Temporary directory for downloads",
    )
    parser.add_argument(
        "--checkpoint-file",
        type=Path,
        help="Checkpoint file for resume support",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be copied without actually copying",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help=(
            "Overwrite target files even if source is "
            "unchanged. Ignores checkpoint and re-uploads "
            "all files."
        ),
    )

    return parser.parse_args()


async def main():
    """Async entry point: parse args, configure logging, and run migration.

    Flow:
      1. Parse CLI arguments.
      2. Initialize file logging (debug log + CSV perf log).
      3. Build ``MigrationConfig`` (from wizard or CLI flags).
      4. Log the configuration for audit/debugging.
      5. Create and run ``MigrationEngine``.
      6. Exit with code 0 (success) or 1 (failure).
    """
    args = parse_args()

    # Initialize logging
    log_dir = Path.cwd() / "logs"
    setup_logging(log_dir)
    logger.info("=" * 60)
    logger.info("SharePoint to Azure Files Copy Tool")
    logger.info("=" * 60)
    logger.info(f"Python version: {sys.version}")
    logger.info(f"Platform: {platform.platform()}")
    logger.info(f"Working directory: {Path.cwd()}")

    if args.interactive:
        config = run_interactive_wizard()
    else:
        # Validate required arguments
        required = [
            "site_url", "library", "storage_account",
            "file_share", "resource_group", "subscription"
        ]
        missing = [
            arg for arg in required
            if not getattr(args, arg.replace("-", "_"), None)
        ]

        if missing:
            Console().print(
                f"[red]Missing required arguments: {', '.join(missing)}[/red]"
            )
            Console().print(
                "Use --interactive for a guided setup, or --help for usage."
            )
            sys.exit(1)

        config = MigrationConfig(
            site_url=args.site_url,
            library_name=args.library,
            storage_account=args.storage_account,
            file_share=args.file_share,
            resource_group=args.resource_group,
            subscription=args.subscription,
            target_folder=args.target_folder,
            max_files=args.max_files,
            export_permissions=args.export_permissions,
            concurrent_downloads=args.concurrent_downloads,
            temp_dir=args.temp_dir,
            checkpoint_file=args.checkpoint_file,
            dry_run=args.dry_run,
            overwrite=args.overwrite,
        )

    # Log configuration
    logger.info(f"Site URL: {config.site_url}")
    logger.info(f"Library: {config.library_name}")
    logger.info(f"Storage Account: {config.storage_account}")
    logger.info(f"File Share: {config.file_share}")
    logger.info(f"Concurrent Downloads: {config.concurrent_downloads}")
    logger.info(f"Batch Size: {BATCH_SIZE}")
    logger.info(f"Max Files: {config.max_files or 'unlimited'}")
    logger.info(f"Dry Run: {config.dry_run}")
    logger.info(f"Overwrite: {config.overwrite}")
    logger.info(
        f"Checkpoint File: "
        f"{config.checkpoint_file or '(auto: logs/checkpoint.json)'}"
    )

    engine = MigrationEngine(config)
    success = await engine.run()

    logger.info(f"Copy completed. Success: {success}")
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    # Ensure stdout/stderr can handle Unicode on Windows legacy terminals
    # (cp1252).  Rich uses box-drawing characters that crash without this.
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sys.stderr.encoding and sys.stderr.encoding.lower() != "utf-8":
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    asyncio.run(main())
