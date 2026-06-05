"""
verify.py — Prove ownership of a Bitcoin address from a BIP39 mnemonic.

Given a public Bitcoin address and a 12/24-word seed phrase, this script
re-derives the wallet's addresses (BIP84 / native SegWit) and checks whether
any of them matches the address you provided. A match proves that the seed
phrase controls the address — i.e. that you are its rightful owner.

Usage:
    poetry run python verify.py <address> "<word1 word2 ... wordN>" [passphrase]

Examples:
    poetry run python verify.py bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu \
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

Exit codes:
    0 = the address belongs to this seed (ownership confirmed)
    1 = no match found (the seed does NOT control this address) or bad input

Notes:
    - Matches the derivation used by btc.py: BIP84, path m/84'/0'/0'/0/0.
      To be robust, it scans the external chain (receiving) and the internal
      chain (change), indexes 0..GAP_LIMIT-1, account 0.
    - The mnemonic is read but never stored or transmitted. Run offline.
"""

import sys
import hashlib
import hmac
import struct

import ecdsa
import bech32
from mnemonic import Mnemonic

# How many address indexes to scan per chain (receiving + change).
GAP_LIMIT = 20

# BIP84 account-level prefix: m/84'/0'/0'
ACCOUNT_PATH = "m/84'/0'/0'"


def hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()


def compressed_pubkey(privkey: bytes) -> bytes:
    """Return the 33-byte compressed SEC1 public key for a private key."""
    sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    x = vk.to_string()[:32]
    y_is_even = vk.to_string()[-1] % 2 == 0
    return (b"\x02" if y_is_even else b"\x03") + x


def CKD_priv(parent_privkey: bytes, parent_chaincode: bytes, index: int):
    """BIP32 private child key derivation."""
    hardened = index >= 0x80000000
    if hardened:
        data = b"\x00" + parent_privkey + struct.pack(">L", index)
    else:
        data = compressed_pubkey(parent_privkey) + struct.pack(">L", index)

    I = hmac_sha512(parent_chaincode, data)
    IL, IR = I[:32], I[32:]

    child = (int.from_bytes(IL, "big") + int.from_bytes(parent_privkey, "big")) % ecdsa.SECP256k1.order
    return child.to_bytes(32, "big"), IR


def derive_path(path: str, priv: bytes, chain: bytes):
    for e in path.split("/")[1:]:  # skip leading "m"
        index = int(e[:-1]) + 0x80000000 if e.endswith("'") else int(e)
        priv, chain = CKD_priv(priv, chain, index)
    return priv, chain


def p2wpkh_address(privkey: bytes) -> str:
    """Native SegWit (bech32, P2WPKH) address for a private key."""
    pub = compressed_pubkey(privkey)
    sha = hashlib.sha256(pub).digest()
    rip = hashlib.new("ripemd160", sha).digest()
    return bech32.encode("bc", 0, rip)


def normalize_address(addr: str) -> str:
    return addr.strip().lower()


def verify(address: str, mnemonic: str, passphrase: str = "") -> str | None:
    """Return the matching derivation path if found, else None."""
    target = normalize_address(address)

    # Basic shape check on the target so we fail loudly on a typo'd address.
    hrp, prog = bech32.decode("bc", target)
    if prog is None:
        raise ValueError(
            f"'{address}' is not a valid bech32 'bc1...' address. "
            "This verifier only handles native SegWit (BIP84) addresses."
        )

    mnemo = Mnemonic("english")
    if not mnemo.check(mnemonic):
        raise ValueError(
            "Invalid BIP39 mnemonic: the words or checksum are wrong "
            "(check spelling, order, and word count)."
        )

    seed = mnemo.to_seed(mnemonic, passphrase=passphrase)
    I = hmac_sha512(b"Bitcoin seed", seed)
    master_priv, master_chain = I[:32], I[32:]

    account_priv, account_chain = derive_path(ACCOUNT_PATH, master_priv, master_chain)

    for change in (0, 1):  # 0 = receiving, 1 = change
        chain_priv, chain_code = CKD_priv(account_priv, account_chain, change)
        for index in range(GAP_LIMIT):
            leaf_priv, _ = CKD_priv(chain_priv, chain_code, index)
            if p2wpkh_address(leaf_priv) == target:
                return f"{ACCOUNT_PATH}/{change}/{index}"
    return None


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__.strip())
        print("\nError: missing arguments.", file=sys.stderr)
        return 1

    address = sys.argv[1]
    mnemonic = " ".join(sys.argv[2].split())  # collapse whitespace
    passphrase = sys.argv[3] if len(sys.argv) > 3 else ""

    try:
        match = verify(address, mnemonic, passphrase)
    except ValueError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return 1

    if match:
        print(f"✅ OWNERSHIP CONFIRMED")
        print(f"   Address : {address}")
        print(f"   Path    : {match}")
        print(f"   This seed phrase controls the address. You are the rightful owner.")
        return 0

    print(f"❌ NO MATCH", file=sys.stderr)
    print(f"   Address : {address}", file=sys.stderr)
    print(
        f"   This seed does NOT control the address within the first "
        f"{GAP_LIMIT} BIP84 indexes (receiving + change).",
        file=sys.stderr,
    )
    print(
        "   Do NOT send funds to this address expecting to recover them with this seed.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
