
from __future__ import annotations

import hashlib
import json
import os
import zipfile
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

def _app_data_root() -> str:
    root = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    directory = os.path.join(root, "UEDumper")
    os.makedirs(directory, exist_ok=True)
    return directory

def default_sharepacks_dir() -> str:
    directory = os.path.join(_app_data_root(), "sharepacks")
    os.makedirs(directory, exist_ok=True)
    return directory

def _safe_name(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in (value or "dump"))
    cleaned = cleaned.strip("_")
    return cleaned or "dump"

def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(64 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()

def _iter_offsets_files(offsets_dir: str) -> List[Tuple[str, str]]:
    files: List[Tuple[str, str]] = []
    for root, _, names in os.walk(offsets_dir):
        for name in sorted(names):
            abs_path = os.path.join(root, name)
            rel_path = os.path.relpath(abs_path, offsets_dir).replace("\\", "/")
            files.append((abs_path, rel_path))
    return files

def create_share_pack(
    offsets_dir: str,
    *,
    game_name: str,
    trust_status: str,
    trust_reason: str,
    latest_update_date: str = "",
    health_state: str = "",
    source: str = "",
    sharepacks_dir: Optional[str] = None,
    extra_metadata: Optional[Dict[str, object]] = None,
) -> Tuple[str, Dict[str, object]]:
    if not offsets_dir or not os.path.isdir(offsets_dir):
        raise FileNotFoundError(f"Offsets directory not found: {offsets_dir}")

    out_dir = sharepacks_dir or default_sharepacks_dir()
    os.makedirs(out_dir, exist_ok=True)

    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%d_%H%M%S")
    zip_name = f"{_safe_name(game_name)}_{stamp}.zip"
    zip_path = os.path.join(out_dir, zip_name)

    files_meta: List[Dict[str, object]] = []
    source_files = _iter_offsets_files(offsets_dir)
    for abs_path, rel_path in source_files:
        try:
            size = int(os.path.getsize(abs_path))
        except OSError:
            size = 0
        files_meta.append(
            {
                "path": rel_path,
                "size": size,
                "sha256": _sha256_file(abs_path),
            }
        )

    manifest: Dict[str, object] = {
        "schema_version": 1,
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "game": game_name,
        "trust": {
            "status": trust_status,
            "reason": trust_reason,
            "latest_update_date": latest_update_date,
            "health_state": health_state,
            "source": source,
        },
        "offsets_dir": os.path.abspath(offsets_dir),
        "files": files_meta,
    }
    if extra_metadata:
        manifest["metadata"] = dict(extra_metadata)

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for abs_path, rel_path in source_files:
            archive.write(abs_path, arcname=f"Offsets/{rel_path}")
        archive.writestr("share_manifest.json", json.dumps(manifest, indent=2))

    return zip_path, manifest
