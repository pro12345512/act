#!/usr/bin/env python3
"""
InteliScale Client License Verification Module (Reference for scale.py)

Supports Dual-Mode Versioned Licenses:
  - Version 1 (v1): Legacy 12-char HMAC code (XXXX-XXXX-XXXX)
  - Version 2 (v2): Ed25519 Asymmetric Digital Signature (IS2.<payload>.<signature>)
"""

import hmac
import hashlib
import json
import base64
import time
from typing import Tuple, Dict, Any, Optional

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


def canonical_json(obj: Any) -> str:
    """Produces deterministic canonical JSON matching Node.js canonicalStringify."""
    return json.dumps(obj, separators=(',', ':'), sort_keys=True)


def base64url_decode(s: str) -> bytes:
    """Decodes standard base64url string with padding."""
    rem = len(s) % 4
    if rem > 0:
        s += '=' * (4 - rem)
    return base64.urlsafe_b64decode(s.encode('ascii'))


# =====================================================================
# Version 1 (v1): Legacy HMAC Verification
# =====================================================================
def verify_v1_hmac(client_hid: str, code: str, secret_key: str) -> bool:
    """
    Verifies a 12-character legacy activation code (e.g., '9F61-A19E-B2F3').
    """
    if not client_hid or not code or not secret_key:
        return False
    clean_hid = client_hid.strip().upper().encode('utf-8')
    h = hmac.new(secret_key.encode('utf-8'), clean_hid, hashlib.sha256).hexdigest().upper()
    expected = f"{h[0:4]}-{h[4:8]}-{h[8:12]}"
    return hmac.compare_digest(expected, code.strip().upper())


# =====================================================================
# Version 2 (v2): Next-Gen Ed25519 Signature Verification
# =====================================================================
def verify_v2_ed25519(
    client_hid: str,
    license_key: str,
    public_key_pem: str
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Verifies an Ed25519 digital signature license (IS2.<payload>.<signature>).
    
    Returns:
        (is_valid: bool, message: str, payload_dict: Optional[dict])
    """
    if not HAS_CRYPTOGRAPHY:
        return False, "Python cryptography library is not installed", None

    parts = license_key.strip().split('.')
    if len(parts) != 3 or parts[0] != 'IS2':
        return False, "Invalid license key format (must start with IS2.)", None

    try:
        # 1. Decode payload
        raw_payload = base64url_decode(parts[1]).decode('utf-8')
        payload = json.loads(raw_payload)
        signature_bytes = bytes.fromhex(parts[2])

        # 2. Canonical JSON data for signature
        canonical_data = canonical_json(payload).encode('utf-8')

        # 3. Verify Ed25519 signature using Public Key
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        public_key.verify(signature_bytes, canonical_data)

        # 4. Verify machine hardware ID matches
        clean_hid = client_hid.strip().upper()
        if payload.get('hid') != clean_hid:
            return False, f"License is bound to machine {payload.get('hid')}, not {clean_hid}", payload

        # 5. Verify expiration
        exp = payload.get('exp', 0)
        now = int(time.time())
        if exp > 0 and now > exp:
            return False, "License has expired", payload

        return True, "License valid and authentic", payload

    except Exception as e:
        return False, f"Signature verification failed: {str(e)}", None


# =====================================================================
# Dual-Mode Dispatcher
# =====================================================================
def verify_any_license(
    client_hid: str,
    license_input: str,
    v1_secret: Optional[str] = None,
    v2_public_key_pem: Optional[str] = None
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Auto-detects license format (v1 or v2) and validates accordingly.
    Ensures seamless migration without breaking older client installations.
    """
    trimmed = license_input.strip()
    if trimmed.startswith('IS2.'):
        if not v2_public_key_pem:
            return False, "Public key not configured for v2 licenses", None
        return verify_v2_ed25519(client_hid, trimmed, v2_public_key_pem)
    else:
        if not v1_secret:
            return False, "Secret key not configured for v1 licenses", None
        ok = verify_v1_hmac(client_hid, trimmed, v1_secret)
        return (ok, "v1 HMAC valid" if ok else "v1 HMAC invalid", {"v": 1} if ok else None)


if __name__ == '__main__':
    print("Testing InteliScale License Verification Module in Python...")

    # Test v1 HMAC
    test_hid = "94E8565A211C99D2"
    test_secret = "InteliSoft_Secure_2026_Key"
    test_code = "9F61-A19E-B2F3"
    assert verify_v1_hmac(test_hid, test_code, test_secret), "v1 HMAC test failed"
    assert not verify_v1_hmac(test_hid, "0000-0000-0000", test_secret), "v1 fake code should fail"
    print("✔ Python v1 HMAC test passed.")

    # Test v2 if cryptography is installed
    if HAS_CRYPTOGRAPHY:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization

        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        pub_pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        payload = {"v": 2, "hid": test_hid, "iat": int(time.time()), "exp": int(time.time()) + 3600, "type": "PRO"}
        canonical = canonical_json(payload).encode('utf-8')
        sig = priv.sign(canonical).hex().upper()
        encoded_payload = base64.urlsafe_b64encode(canonical).decode('ascii').rstrip('=')
        lic_key = f"IS2.{encoded_payload}.{sig}"

        ok, msg, _ = verify_v2_ed25519(test_hid, lic_key, pub_pem)
        assert ok, f"v2 Ed25519 test failed: {msg}"

        # Tampered signature check
        tampered = lic_key[:-2] + "00"
        ok_bad, _, _ = verify_v2_ed25519(test_hid, tampered, pub_pem)
        assert not ok_bad, "Tampered signature should fail"

        print("✔ Python v2 Ed25519 test passed.")
        print("ALL PYTHON SCALE CLIENT TESTS PASSED!")
