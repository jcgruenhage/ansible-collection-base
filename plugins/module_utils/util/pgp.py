# (c) 2026, JC Grünhage
# GNU Affero General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/agpl-3.0.txt)

"""PGPy and PGP_CERT_D: recipient listing from ciphertext, pgp_cert_d path resolution, sync from GnuPG."""

from __future__ import annotations

from copy import copy
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Iterator,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
)

from . import register_missing_import

_HEX = frozenset("0123456789abcdef")

if TYPE_CHECKING:
    from pgpy import PGPKey, PGPKeyring, PGPMessage
else:
    try:
        from pgpy import PGPKey, PGPKeyring, PGPMessage
    except ImportError:
        register_missing_import("PGPy")


# PGP_CERT_D layout: {pgp_cert_d_path}/{first2_hex}/{remaining_hex} (lowercase)
def _pgp_cert_d_path_for_fingerprint(pgp_cert_d_path: Path, fingerprint: str) -> Path:
    """Path to cert file for a 40-char primary fingerprint (lowercase hex)."""
    if validate_fingerprint_or_keyid(fingerprint) != "fingerprint":
        raise ValueError(
            "Expected 40-char primary fingerprint, got %r" % (fingerprint,)
        )
    fp = _normalize_hex(fingerprint)
    return pgp_cert_d_path / fp[:2] / fp[2:]


def _normalize_hex(s: str) -> str:
    return s.strip().lower().replace(" ", "")


def validate_fingerprint_or_keyid(
    fingerprint_or_keyid: str,
) -> Literal["fingerprint", "keyid"]:
    """Raise ValueError if fingerprint_or_keyid is not a valid 16- or 40-char hex string.
    States in the exception message what is invalid.
    """
    query = _normalize_hex(fingerprint_or_keyid)
    if not query:
        raise ValueError("fingerprint or keyid must not be empty")
    if len(query) not in (16, 40):
        raise ValueError(
            "fingerprint (40 hex chars) or keyid (16 hex chars) required, got %d character(s)"
            % len(query)
        )
    for c in query:
        if c not in _HEX:
            raise ValueError(
                "fingerprint or keyid must contain only hex digits (0-9, a-f), got invalid character %r"
                % c
            )
    if len(query) == 40:
        return "fingerprint"
    return "keyid"


def iter_cert_paths_in_pgp_cert_d(pgp_cert_d_path: Path) -> Iterator[Path]:
    """Yield each cert file path in PGP_CERT_D under fingerprint-mapped paths only (3.2.1).
    Ignores special names and _*. Caller is responsible for PGPKey.from_file(path) and any load errors.
    """
    if not pgp_cert_d_path.is_dir():
        return
    for subdir in pgp_cert_d_path.iterdir():
        if (
            not subdir.is_dir()
            or len(subdir.name) != 2
            or not all(c in _HEX for c in subdir.name)
        ):
            continue
        for entry in subdir.iterdir():
            if (
                len(entry.name) == 38
                and all(c in _HEX for c in entry.name)
                and entry.is_file()
            ):
                yield entry


def cert_matches_fingerprint_or_keyid(
    key: PGPKey,
    query: str,
    kind: Literal["fingerprint", "keyid"],
) -> bool:
    """True if key's primary or any subkey matches query (normalized hex).
    Caller must have validated; query and kind are the result of validate_fingerprint_or_keyid + _normalize_hex.
    PGPy fingerprints/keyids are assumed to be 40/16 hex chars after normalizing.
    """
    key_to_str = (
        (lambda k: _normalize_hex(str(k.fingerprint)))
        if kind == "fingerprint"
        else (lambda k: _normalize_hex(str(k.fingerprint.keyid)))
    )
    keys_to_check = [key] + list((key.subkeys or {}).values())
    return any(key_to_str(k) == query for k in keys_to_check)


def cert_fingerprints_and_keyids(key: PGPKey) -> Tuple[Set[str], Set[str]]:
    """Return (fingerprints, keyids) for the primary key and all subkeys (normalized hex).
    Fingerprints are 40-char, keyids 16-char. PGPy is assumed to give those lengths after normalizing.
    """
    fingerprints = {_normalize_hex(str(key.fingerprint))}
    keyids = {_normalize_hex(str(key.fingerprint.keyid))}
    for subkey in (key.subkeys or {}).values():
        fingerprints.add(_normalize_hex(str(subkey.fingerprint)))
        keyids.add(_normalize_hex(str(subkey.fingerprint.keyid)))
    return (fingerprints, keyids)


def find_cert_in_pgp_cert_d(
    pgp_cert_d_path: Path, fingerprint_or_keyid: str
) -> Optional[PGPKey]:
    """Find a cert in PGP_CERT_D whose primary or any subkey matches the given 40-char fingerprint or 16-char keyid.
    Returns the PGPKey (cert) or None. Only considers fingerprint-mapped paths (3.2.1); ignores special names and _*.
    Raises ValueError for invalid fingerprint_or_keyid (see validate_fingerprint_or_keyid).
    """
    kind = validate_fingerprint_or_keyid(fingerprint_or_keyid)
    query = _normalize_hex(fingerprint_or_keyid)
    for path in iter_cert_paths_in_pgp_cert_d(pgp_cert_d_path):
        key, _unused = PGPKey.from_file(path)
        if cert_matches_fingerprint_or_keyid(key, query, kind):
            return key
    return None


def merge_cert(base: PGPKey, other: PGPKey) -> PGPKey:
    """Merge other (PGPKey, same fingerprint as base) into a copy of base; return the copy."""
    merged = copy(base)
    for subkey in other.subkeys.values():
        merged |= copy(subkey)
    for uid in other.userids:
        merged |= copy(uid)
        if uid.selfsig is not None:
            merged |= copy(uid.selfsig)
        for sig in uid.third_party_certifications:
            merged |= copy(sig)
    for ua in other.userattributes:
        merged |= copy(ua)
        if ua.selfsig is not None:
            merged |= copy(ua.selfsig)
        for sig in ua.third_party_certifications:
            merged |= copy(sig)
    for sig in other.self_signatures:
        merged |= copy(sig)
    for sig in other.revocation_signatures:
        merged |= copy(sig)
    return merged


def get_recipient_key_ids(ciphertext_bytes: bytes) -> List[str]:
    """Parse ciphertext with PGPy; return list of recipient (subkey) long key IDs (16-char hex)."""
    msg = PGPMessage.from_blob(ciphertext_bytes)
    return sorted(str(e) for e in msg.encrypters)


def sync_gnupg_to_pgp_cert_d(pgp_cert_d_path: Path) -> None:
    """Export all public keys from GnuPG (default keyring) and import into PGP_CERT_D, merging with existing."""
    from . import gpg as gpg_util

    raw = gpg_util.run_gpg(["--export"], stdin=None)
    if not raw.strip():
        return
    keyring: Any = PGPKeyring()
    keyring.load(raw)

    for fp in keyring.fingerprints(keyhalf="public", keytype="primary"):
        path = _pgp_cert_d_path_for_fingerprint(pgp_cert_d_path, str(fp))
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_file():
            with open(path, "rb") as f:
                existing_cert = f.read()
            base_key, _unused = PGPKey.from_blob(existing_cert)
            with keyring.key(fp) as k:
                merged_key = merge_cert(base_key, k.pubkey)
            data = bytes(merged_key.pubkey)
        else:
            with keyring.key(fp) as k:
                data = bytes(k.pubkey)
        with open(path, "wb") as f:
            f.write(data)


def diff_recipients(
    actual_recipients: List[str],
    wanted_recipients: List[str],
    pgp_cert_d_path: Path,
    *,
    sync_from_gpg_if_missing: bool = True,
) -> Any:
    """Diff actual recipients (from ciphertext) vs wanted (from .gpg-id; may be fingerprint or keyid).
    For each wanted ID, find the cert in pgp_cert_d; if the cert's fingerprints/keyids intersect actual,
    that wanted is covered and the cert's primary fingerprint goes into matched. Sync from GnuPG once if
    any wanted cert was not found, then retry uncovered.
    Returns a dict: matched (bool), missing (list), extra (list).
    """
    wanted_set = {_normalize_hex(r) for r in wanted_recipients if r.strip()}
    actual_sets: Dict[Literal["fingerprint", "keyid"], Set[str]] = {
        "fingerprint": set(),
        "keyid": set(),
    }
    for a in actual_recipients:
        actual_sets[validate_fingerprint_or_keyid(a)].add(_normalize_hex(a))
    covered_wanted = set()
    matched_identifiers = set()

    def process_wanted(w: str) -> None:
        try:
            cert = find_cert_in_pgp_cert_d(pgp_cert_d_path, w)
        except ValueError as e:
            raise ValueError(
                "Wanted recipient %r cannot be matched to an existing key in the cert store: %s"
                % (w, e)
            ) from e
        if cert is None:
            raise ValueError(
                "Wanted recipient %r has no matching cert in the cert store" % (w,)
            )
        fps, keyids = cert_fingerprints_and_keyids(cert)
        if (fps & actual_sets["fingerprint"]) or (keyids & actual_sets["keyid"]):
            covered_wanted.add(w)
            matched_identifiers.update(fps | keyids)

    for w in wanted_set:
        process_wanted(w)
    if sync_from_gpg_if_missing and (wanted_set - covered_wanted):
        sync_gnupg_to_pgp_cert_d(pgp_cert_d_path)
        for w in wanted_set - covered_wanted:
            process_wanted(w)

    missing = list(wanted_set - covered_wanted)
    extra = [
        a for a in actual_recipients if _normalize_hex(a) not in matched_identifiers
    ]
    return {
        "matched": len(missing) == 0 and len(extra) == 0,
        "missing": missing,
        "extra": extra,
    }


def resolve_fingerprint_to_pgp_cert_d_path(
    pgp_cert_d_path: Path, fingerprint: str
) -> Path:
    """Resolve fingerprint or keyid (40- or 16-char) to path to cert file in PGP_CERT_D.
    For 40-char fingerprints, tries the direct path first (avoids PGPy dependency).
    Falls back to scanning all certs for keyids or subkey fingerprints.
    """
    kind = validate_fingerprint_or_keyid(fingerprint)
    if kind == "fingerprint":
        direct = _pgp_cert_d_path_for_fingerprint(pgp_cert_d_path, fingerprint)
        if direct.is_file():
            return direct
    cert = find_cert_in_pgp_cert_d(pgp_cert_d_path, fingerprint)
    if cert is None:
        raise ValueError(
            "Could not resolve fingerprint/keyid %s to a cert in pgp_cert_d"
            % fingerprint
        )
    primary_fp = _normalize_hex(str(cert.fingerprint))
    return _pgp_cert_d_path_for_fingerprint(pgp_cert_d_path, primary_fp)
