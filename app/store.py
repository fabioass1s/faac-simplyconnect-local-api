"""Guarda as chaves dos portões num JSON simples (data/keys.json).

Estrutura:
  { "<access_point_id>": {
        "name", "serial", "device_public_key",
        "browser_name", "browser_id", "uuidm", "private_key"
  } }

A private_key fica em texto puro. É tão sensível quanto a senha do portão —
data/ está no .gitignore. Cada chave também é anexada a um log append-only
(keys-backup.jsonl) que nunca é sobrescrito, como rede de segurança.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_FILE = _DATA_DIR / "keys.json"
_BACKUP = _DATA_DIR / "keys-backup.jsonl"
_LOCK = threading.Lock()


def _read() -> dict:
    if not _FILE.exists():
        return {}
    try:
        return json.loads(_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _write(data: dict) -> None:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    _FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def all_keys() -> dict:
    return _read()


def get_key(ap_id: str) -> Optional[dict]:
    return _read().get(ap_id)


def save_key(ap_id: str, rec: dict) -> None:
    with _LOCK:
        data = _read()
        data[ap_id] = rec
        _write(data)
    append_backup({"access_point_id": ap_id, **rec})


def delete_key(ap_id: str) -> bool:
    with _LOCK:
        data = _read()
        if ap_id not in data:
            return False
        del data[ap_id]
        _write(data)
        return True


def append_backup(rec: dict) -> None:
    """Anexa ao log append-only (nunca sobrescreve)."""
    entry = {**rec, "ts": datetime.now(timezone.utc).isoformat()}
    with _LOCK:
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        with _BACKUP.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
