"""
send.py — Swap BTC -> USDC/USDT (Ethereum) from your self-custody wallet,
without connecting a browser wallet.

It does the inverse of a "buy" on THORSwap: it spends BTC from the wallet
controlled by your seed phrase and asks THORChain to deliver USDC or USDT to
your Ethereum address. The whole thing is built and signed locally; your seed
never leaves the machine.

How it stays safe:
  * The THORChain deposit address AND the swap memo come straight from
    THORChain's official quote API — never hand-crafted here (a wrong memo can
    burn funds, so we don't invent one).
  * If THORChain trading is halted, the quote fails and the script aborts.
  * Every input signature is re-verified before the transaction is accepted.
  * It DOES NOT broadcast unless you pass --broadcast AND type a confirmation.
    By default it prints the signed transaction hex for you to inspect/broadcast.

Usage:
  poetry run python send.py --to USDC --dest 0xYourEthAddress \
      --amount-btc 0.01 --mnemonic "word1 word2 ... word12" [--broadcast]

  poetry run python send.py --to USDT --dest 0x... --max \
      --mnemonic "..." --expected-from bc1qYourAddr --broadcast

Important:
  * THORChain deposit (vault) addresses ROTATE. Broadcast promptly after
    building — if you wait too long the quote expiry passes and you must re-run.
  * For large swaps keep streaming enabled (default) to reduce slippage.
  * Always do a small test swap first.
"""

import argparse
import hashlib
import hmac
import json
import math
import struct
import sys
import urllib.request
import urllib.error

import ecdsa
from ecdsa.util import sigdecode_der
import bech32
from mnemonic import Mnemonic

from bitcoin import SelectParams
from bitcoin.core import (
    CMutableTransaction, CMutableTxIn, CMutableTxOut, COutPoint,
    CTxInWitness, CTxWitness, CScriptWitness, lx, b2x, Hash160,
)
from bitcoin.core.script import (
    CScript, OP_0, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, OP_RETURN,
    SignatureHash, SIGHASH_ALL, SIGVERSION_WITNESS_V0,
)
from bitcoin.wallet import CBitcoinSecret, CBitcoinAddress

SelectParams("mainnet")

# THORChain full asset identifiers (the quote API also accepts these).
ASSETS = {
    "USDC": "ETH.USDC-0XA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48",
    "USDT": "ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7",
}

DEFAULT_THORNODE = "https://thornode.ninerealms.com"   # fallback: https://thornode.thorchain.liquify.com
DEFAULT_MEMPOOL = "https://mempool.space/api"
CLIENT_ID = "btc-wallet-generator"

P2WPKH_OUTPUT_DUST = 330  # sats; change below this is uneconomical, fold into fee


# ----------------------------------------------------------------------------
# BIP39 / BIP32 / BIP84 derivation (same scheme as btc.py / verify.py)
# ----------------------------------------------------------------------------
def hmac_sha512(key, data):
    return hmac.new(key, data, hashlib.sha512).digest()


def compressed_pubkey(privkey):
    sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return (b"\x02" if vk.to_string()[-1] % 2 == 0 else b"\x03") + vk.to_string()[:32]


def CKD_priv(parent_privkey, parent_chaincode, index):
    if index >= 0x80000000:
        data = b"\x00" + parent_privkey + struct.pack(">L", index)
    else:
        data = compressed_pubkey(parent_privkey) + struct.pack(">L", index)
    I = hmac_sha512(parent_chaincode, data)
    child = (int.from_bytes(I[:32], "big") + int.from_bytes(parent_privkey, "big")) % ecdsa.SECP256k1.order
    return child.to_bytes(32, "big"), I[32:]


def derive(mnemonic, passphrase, account, change, index):
    mnemo = Mnemonic("english")
    if not mnemo.check(mnemonic):
        raise SystemExit("❌ Invalid BIP39 mnemonic (words or checksum wrong).")
    seed = mnemo.to_seed(mnemonic, passphrase=passphrase)
    I = hmac_sha512(b"Bitcoin seed", seed)
    priv, chain = I[:32], I[32:]
    path = [84 + 0x80000000, 0 + 0x80000000, account + 0x80000000, change, index]
    for i in path:
        priv, chain = CKD_priv(priv, chain, i)
    pub = compressed_pubkey(priv)
    h160 = Hash160(pub)
    addr = bech32.encode("bc", 0, h160)
    return priv, pub, h160, addr


# ----------------------------------------------------------------------------
# Network helpers (read-only except the explicit broadcast)
# ----------------------------------------------------------------------------
def http_get_json(url):
    req = urllib.request.Request(url, headers={"x-client-id": CLIENT_ID, "User-Agent": CLIENT_ID})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def http_get_text(url):
    req = urllib.request.Request(url, headers={"x-client-id": CLIENT_ID, "User-Agent": CLIENT_ID})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode().strip()


def get_quote(thornode, to_asset, dest, amount_sats, tolerance_bps, stream):
    params = [
        "from_asset=BTC.BTC",
        f"to_asset={to_asset}",
        f"amount={amount_sats}",
        f"destination={dest}",
        f"tolerance_bps={tolerance_bps}",
    ]
    if stream:
        params.append("streaming_interval=1")
    url = f"{thornode}/thorchain/quote/swap?" + "&".join(params)
    try:
        data = http_get_json(url)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        raise SystemExit(f"❌ THORChain quote failed (HTTP {e.code}): {body}")
    if "memo" not in data or "inbound_address" not in data:
        msg = data.get("message") or data
        raise SystemExit(f"❌ THORChain will not quote this swap (trading halted or invalid?):\n   {msg}")
    return data


def get_utxos(mempool, addr):
    utxos = http_get_json(f"{mempool}/address/{addr}/utxo")
    return [u for u in utxos if u.get("status", {}).get("confirmed", False)]


def get_fee_rate(mempool):
    return int(http_get_json(f"{mempool}/v1/fees/recommended")["halfHourFee"])


def broadcast(mempool, raw_hex):
    req = urllib.request.Request(f"{mempool}/tx", data=raw_hex.encode(),
                                 headers={"Content-Type": "text/plain", "User-Agent": CLIENT_ID})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode().strip()


# ----------------------------------------------------------------------------
# Fee / coin selection
# ----------------------------------------------------------------------------
def est_vsize(n_in, n_p2wpkh_out, memo_len):
    base = 10.5
    opret = 8 + 1 + (2 + memo_len)  # value + script-len varint + (OP_RETURN + push + memo)
    return math.ceil(base + n_in * 68 + n_p2wpkh_out * 31 + opret)


def select_coins(utxos, target, fee_rate, memo_len):
    """Pick UTXOs (largest first) to cover target + fee. Returns (selected, fee, change)."""
    utxos = sorted(utxos, key=lambda u: u["value"], reverse=True)
    selected, total = [], 0
    for u in utxos:
        selected.append(u)
        total += u["value"]
        fee_with_change = est_vsize(len(selected), 2, memo_len) * fee_rate
        if total >= target + fee_with_change:
            change = total - target - fee_with_change
            if change >= P2WPKH_OUTPUT_DUST:
                return selected, int(fee_with_change), int(change)
            # Change is dust → drop it, recompute single-output fee, burn remainder to fee
            fee_no_change = est_vsize(len(selected), 1, memo_len) * fee_rate
            if total >= target + fee_no_change:
                return selected, int(total - target), 0
    raise SystemExit(
        f"❌ Insufficient funds: have {total} sats, need {target} + fees for this swap."
    )


# ----------------------------------------------------------------------------
# Transaction build + sign
# ----------------------------------------------------------------------------
def build_and_sign(priv, pub, h160, selected, vault_addr, memo, vault_amount, change, from_h160):
    txins = [CMutableTxIn(COutPoint(lx(u["txid"]), u["vout"])) for u in selected]

    outs = [CMutableTxOut(vault_amount, CBitcoinAddress(vault_addr).to_scriptPubKey())]
    outs.append(CMutableTxOut(0, CScript([OP_RETURN, memo.encode()])))
    if change > 0:
        outs.append(CMutableTxOut(change, CScript([OP_0, from_h160])))

    tx = CMutableTransaction(txins, outs)
    scriptCode = CScript([OP_DUP, OP_HASH160, h160, OP_EQUALVERIFY, OP_CHECKSIG])
    seckey = CBitcoinSecret.from_secret_bytes(priv, compressed=True)
    vk = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1).verifying_key

    witnesses = []
    for i, u in enumerate(selected):
        sighash = SignatureHash(scriptCode, tx, i, SIGHASH_ALL, u["value"], SIGVERSION_WITNESS_V0)
        sig = seckey.sign(sighash) + bytes([SIGHASH_ALL])
        # Self-check: the signature MUST verify, or we refuse to continue.
        if not vk.verify_digest(sig[:-1], sighash, sigdecode=sigdecode_der):
            raise SystemExit(f"❌ Internal error: signature for input {i} failed self-verification.")
        witnesses.append(CTxInWitness(CScriptWitness([sig, pub])))
    tx.wit = CTxWitness(witnesses)
    return tx


# ----------------------------------------------------------------------------
def fmt_btc(sats):
    return f"{sats/1e8:.8f} BTC ({sats} sats)"


def main():
    p = argparse.ArgumentParser(description="Swap BTC -> USDC/USDT (Ethereum) from your seed-controlled wallet.")
    p.add_argument("--mnemonic", required=True, help="12/24-word BIP39 seed phrase (quoted).")
    p.add_argument("--passphrase", default="", help="Optional BIP39 passphrase (25th word).")
    p.add_argument("--to", required=True, choices=["USDC", "USDT"], help="Stablecoin to receive on Ethereum.")
    p.add_argument("--dest", required=True, help="Your Ethereum (0x...) address to receive the stablecoin.")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--amount-btc", type=float, help="Amount of BTC to swap.")
    g.add_argument("--max", action="store_true", help="Swap the entire confirmed balance.")
    p.add_argument("--account", type=int, default=0, help="BIP84 account index (default 0).")
    p.add_argument("--change", type=int, default=0, help="0=receiving chain, 1=change chain (default 0).")
    p.add_argument("--index", type=int, default=0, help="Address index (default 0).")
    p.add_argument("--expected-from", help="Assert the derived source address equals this (recommended).")
    p.add_argument("--fee-rate", type=int, help="BTC fee rate sat/vByte (default: network estimate).")
    p.add_argument("--tolerance-bps", type=int, default=300, help="Max slippage in basis points (default 300 = 3%%).")
    p.add_argument("--no-stream", action="store_true", help="Disable streaming swap (not recommended for large amounts).")
    p.add_argument("--thornode-url", default=DEFAULT_THORNODE)
    p.add_argument("--mempool-url", default=DEFAULT_MEMPOOL)
    p.add_argument("--broadcast", action="store_true", help="Actually broadcast (otherwise dry-run prints hex only).")
    args = p.parse_args()

    mnemonic = " ".join(args.mnemonic.split())
    dest = args.dest.strip()
    if not (dest.lower().startswith("0x") and len(dest) == 42):
        raise SystemExit(f"❌ '{dest}' is not a valid Ethereum 0x address.")
    to_asset = ASSETS[args.to]

    # 1) Derive the source wallet.
    priv, pub, h160, from_addr = derive(mnemonic, args.passphrase, args.account, args.change, args.index)
    path = f"m/84'/0'/{args.account}'/{args.change}/{args.index}"
    if args.expected_from and args.expected_from.strip().lower() != from_addr:
        raise SystemExit(
            f"❌ Derived address {from_addr} ({path}) does NOT match --expected-from "
            f"{args.expected_from}. Wrong seed/path? Aborting before touching funds."
        )

    # 2) Gather UTXOs + fee rate.
    utxos = get_utxos(args.mempool_url, from_addr)
    if not utxos:
        raise SystemExit(f"❌ No confirmed UTXOs at {from_addr}. Nothing to spend.")
    total_in = sum(u["value"] for u in utxos)
    fee_rate = args.fee_rate if args.fee_rate else get_fee_rate(args.mempool_url)
    stream = not args.no_stream

    # 3) Decide swap amount, then quote THORChain (provisional memo length for --max).
    if args.max:
        approx_fee = est_vsize(len(utxos), 1, 70) * fee_rate
        send_sats = total_in - int(approx_fee)
        if send_sats <= 0:
            raise SystemExit("❌ Balance too small to cover the network fee.")
    else:
        send_sats = int(round(args.amount_btc * 1e8))

    quote = get_quote(args.thornode_url, to_asset, dest, send_sats, args.tolerance_bps, stream)
    memo = quote["memo"]
    vault = quote["inbound_address"]
    dust = int(quote.get("dust_threshold", "10000"))
    rec_min = int(quote.get("recommended_min_amount_in", "0"))
    expected_out = int(quote.get("expected_amount_out", "0"))
    total_swap_seconds = quote.get("total_swap_seconds")
    fees = quote.get("fees", {})

    if send_sats < dust:
        raise SystemExit(f"❌ Amount {send_sats} sats is below THORChain dust threshold {dust}.")
    if rec_min and send_sats < rec_min:
        print(f"⚠️  Amount {send_sats} sats is below THORChain's recommended minimum {rec_min} sats — "
              f"fees may eat a large share.", file=sys.stderr)
    if len(memo.encode()) > 80:
        raise SystemExit(f"❌ Memo is {len(memo.encode())} bytes (>80); standard nodes may reject. Aborting.")

    # 4) Coin selection (re-derive precise fee with the real memo).
    if args.max:
        # Recompute with the real memo: send everything minus the single-output fee.
        fee = est_vsize(len(utxos), 1, len(memo)) * fee_rate
        send_sats = total_in - int(fee)
        selected, change = utxos, 0
        # Re-quote at the finalized amount so memo/limit reflect what we actually send.
        quote = get_quote(args.thornode_url, to_asset, dest, send_sats, args.tolerance_bps, stream)
        memo, vault = quote["memo"], quote["inbound_address"]
        expected_out = int(quote.get("expected_amount_out", "0"))
        fee = int(fee)
    else:
        selected, fee, change = select_coins(utxos, send_sats, fee_rate, len(memo))

    # 5) Build + sign (with per-input signature self-verification).
    tx = build_and_sign(priv, pub, h160, selected, vault, memo, send_sats, change, h160)
    raw = b2x(tx.serialize())
    txid = b2x(tx.GetTxid()[::-1])

    # 6) Summary.
    out_decimals = expected_out / 1e8  # THORChain normalizes output to 8 dp
    print("\n=========================  SWAP SUMMARY  =========================")
    print(f"  Source address   : {from_addr}   ({path})")
    print(f"  Inputs selected  : {len(selected)} UTXO(s), total {fmt_btc(sum(u['value'] for u in selected))}")
    print(f"  Send to vault    : {fmt_btc(send_sats)}")
    print(f"  THORChain vault  : {vault}   ⚠️ rotates — broadcast promptly")
    print(f"  Memo (OP_RETURN) : {memo}")
    print(f"  Change back      : {fmt_btc(change)} -> {from_addr}")
    print(f"  BTC miner fee    : {fee} sats  (@ {fee_rate} sat/vB)")
    print(f"  ----")
    print(f"  Receiving        : ~{out_decimals:,.2f} {args.to} -> {dest}")
    print(f"  Slippage limit   : {args.tolerance_bps} bps   Streaming: {'on' if stream else 'off'}")
    if total_swap_seconds:
        print(f"  Est. swap time   : ~{total_swap_seconds}s")
    if fees:
        print(f"  THORChain fees   : total {int(fees.get('total',0))/1e8:,.2f} {args.to}, "
              f"slippage {fees.get('slippage_bps','?')} bps")
    print(f"  ----")
    print(f"  TXID             : {txid}")
    print("==================================================================\n")
    print("Signed raw transaction:")
    print(raw)
    print()

    # 7) Broadcast only on explicit opt-in + typed confirmation.
    if not args.broadcast:
        print("DRY RUN — not broadcast. Review everything above.")
        print("To send: re-run with --broadcast, or paste the hex into a broadcaster")
        print(f"(e.g. {args.mempool_url}/tx).")
        return

    print("⚠️  About to BROADCAST a real Bitcoin transaction moving "
          f"{fmt_btc(send_sats)} to swap into {args.to}.")
    confirm = input('   Type exactly "SEND" to broadcast: ')
    if confirm.strip() != "SEND":
        raise SystemExit("Aborted — nothing was broadcast.")
    try:
        returned_txid = broadcast(args.mempool_url, raw)
    except urllib.error.HTTPError as e:
        raise SystemExit(f"❌ Broadcast rejected (HTTP {e.code}): {e.read().decode()}")
    print(f"✅ Broadcast. TXID: {returned_txid}")
    print(f"   Track: https://mempool.space/tx/{returned_txid}")
    print(f"   USDC/USDT will arrive at {dest} after THORChain confirms (~minutes).")


if __name__ == "__main__":
    main()
