from mnemonic import Mnemonic
import hashlib
import hmac
import struct
import ecdsa
import base58
import bech32

# ---------------------------------------------
# STEP 1 — Generate 12 or 24-word mnemonic
# ---------------------------------------------
mnemo = Mnemonic("english")
mnemonic = mnemo.generate(strength=128)   # 128 bits = 12 words; 256 bits = 24 words
print("Mnemonic:", mnemonic)

# ---------------------------------------------
# STEP 2 — Convert mnemonic → seed (BIP39)
# ---------------------------------------------
seed = mnemo.to_seed(mnemonic, passphrase="")
print("Seed:", seed.hex())

# ---------------------------------------------
# STEP 3 — BIP32 master key + chain code
# ---------------------------------------------
def hmac_sha512(key, data):
    return hmac.new(key, data, hashlib.sha512).digest()

I = hmac_sha512(b"Bitcoin seed", seed)
master_priv = I[:32]
master_chain = I[32:]

print("Master private key:", master_priv.hex())
print("Master chain code:", master_chain.hex())

# ---------------------------------------------
# BIP32 child derivation (private)
# ---------------------------------------------
def CKD_priv(parent_privkey, parent_chaincode, index):
    hardened = index >= 0x80000000

    if hardened:
        data = b"\x00" + parent_privkey + struct.pack(">L", index)
    else:
        # derive public key
        sk = ecdsa.SigningKey.from_string(parent_privkey, curve=ecdsa.SECP256k1)
        vk = sk.verifying_key
        pubkey = b"\x02" + vk.to_string()[:32] if vk.to_string()[-1] % 2 == 0 else b"\x03" + vk.to_string()[:32]
        data = pubkey + struct.pack(">L", index)

    I = hmac_sha512(parent_chaincode, data)
    IL, IR = I[:32], I[32:]

    child_privkey = (int.from_bytes(IL, "big") + int.from_bytes(parent_privkey, "big")) % ecdsa.SECP256k1.order
    child_privkey = child_privkey.to_bytes(32, "big")

    return child_privkey, IR

# ---------------------------------------------
# STEP 4 — Derive BIP84 path: m/84'/0'/0'/0/0
# ---------------------------------------------
# Hardened indexes = add 0x80000000
def derive_path(path, priv, chain):
    elements = path.split("/")[1:]  # remove "m"

    for e in elements:
        if "'" in e:
            index = int(e[:-1]) + 0x80000000
        else:
            index = int(e)
        priv, chain = CKD_priv(priv, chain, index)
    return priv, chain

path = "m/84'/0'/0'/0/0"
final_priv, final_chain = derive_path(path, master_priv, master_chain)

print(f"Derived private key ({path}):", final_priv.hex())

# ---------------------------------------------
# STEP 5 — Convert private key → WIF
# ---------------------------------------------
extended = b"\x80" + final_priv + b"\x01"  # compressed key
checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
wif = base58.b58encode(extended + checksum).decode()
print("WIF private key:", wif)

# ---------------------------------------------
# STEP 6 — Create compressed public key
# ---------------------------------------------
sk = ecdsa.SigningKey.from_string(final_priv, curve=ecdsa.SECP256k1)
vk = sk.verifying_key

public_key = b"\x02" + vk.to_string()[:32] if vk.to_string()[-1] % 2 == 0 else b"\x03" + vk.to_string()[:32]
print("Public key:", public_key.hex())

# ---------------------------------------------
# STEP 7 — Generate native SegWit bc1 address (P2WPKH)
# ---------------------------------------------
sha = hashlib.sha256(public_key).digest()
rip = hashlib.new("ripemd160", sha).digest()

bc1_address = bech32.encode("bc", 0, rip)
print("Bitcoin address (bech32):", bc1_address)
