"""
archive.py — two distinct archiving features

1. create_investigation_archive() — ALWAYS run, per device: zips that
   device's investigation/ folder into <host_label>/investigation.zip and
   writes a sibling Readme.txt

2. encrypt_output() — OPTIONAL (--encrypt flag), whole-run: AES-256-CBC
   encryption of the entire output directory (every device combined).
"""
from __future__ import annotations

import hashlib
import secrets
import shutil
import subprocess
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple


_README_TEMPLATE = """Forensicator Investigation Archive
===================================

Host      : {host}
Generated : {generated}
Archive   : investigation.zip
SHA256    : {sha256}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Forensicator Enterprise

The investigation archive can be uploaded to
Forensicator Enterprise for:

 • Network device configuration analysis
 • IOC enrichment
 • Cross-device correlation
 • Timeline analysis
 • Case management
 • Team collaboration

Learn more:
https://forensicator.io
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""


def create_investigation_archive(device_dir: Path, host_label: str) -> Optional[Path]:
    """
    Zips <device_dir>/investigation/ into <device_dir>/investigation.zip
    and writes a sibling Readme.txt
    """
    investigation_dir = device_dir / "investigation"
    if not investigation_dir.is_dir():
        return None

    archive_path = device_dir / "investigation.zip"
    try:
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_path in investigation_dir.rglob("*"):
                if file_path.is_file():
                    zf.write(file_path, arcname=file_path.relative_to(investigation_dir))

        sha256 = hashlib.sha256(archive_path.read_bytes()).hexdigest().upper()
        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        readme_text = _README_TEMPLATE.format(host=host_label, generated=generated, sha256=sha256)
        (device_dir / "Readme.txt").write_text(readme_text, encoding="utf-8")
        return archive_path
    except Exception:
        archive_path.unlink(missing_ok=True)
        return None


def encrypt_output(output_root: Path, case: str) -> Optional[Tuple[Path, Path]]:
    """
    Tars every collected device's output under output_root, encrypts the
    tarball with openssl, writes the encryption key to a sibling
    <case>_ENCRYPTION_KEY.txt, and deletes the unencrypted tarball.

    Returns (encrypted_archive_path, key_file_path) on success, or None
    if openssl isn't available or any step failed — never raises, and
    never leaves an unencrypted tarball behind on failure, matching the
    "optional feature degrades gracefully, never blocks the run" pattern.
    """
    if shutil.which("openssl") is None:
        return None

    tarball = output_root / f"{case}_network-investigation.tar.gz"
    encrypted = output_root / f"{case}_network-investigation.tar.gz.enc"
    key_file = output_root / f"{case}_ENCRYPTION_KEY.txt"

    try:
        with tarfile.open(tarball, "w:gz") as tar:
            for item in output_root.iterdir():
                if item.name == tarball.name:
                    continue
                tar.add(item, arcname=item.name)

        password = secrets.token_hex(32)
        result = subprocess.run(
            [
                "openssl", "enc", "-aes-256-cbc", "-salt", "-pbkdf2", "-iter", "100000",
                "-pass", f"pass:{password}", "-in", str(tarball), "-out", str(encrypted),
            ],
            capture_output=True, text=True,
        )
        if result.returncode != 0 or not encrypted.exists():
            return None

        key_file.write_text(
            f"Encryption key for {tarball.name}:\n{password}\n\n"
            "Decrypt with:\n"
            f"openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -pass pass:{password} "
            f"-in {encrypted.name} -out decrypted.tar.gz\n",
            encoding="utf-8",
        )
        tarball.unlink(missing_ok=True)
        return encrypted, key_file
    except Exception:
        tarball.unlink(missing_ok=True)
        return None
