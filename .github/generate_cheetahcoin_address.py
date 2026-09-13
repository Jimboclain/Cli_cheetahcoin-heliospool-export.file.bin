                #!/usr/bin/env python3
                
"""
Generate CheetahCoin-style P2PKH addresses + WIF private keys.

Usage examples:
  # generate one address with defaults (version_byte=0x00, wif_prefix=0x80)
  python generate_cheetahcoin_address.py

  # specify CheetahCoin version byte (hex)
  python generate_cheetahcoin_address.py --version-byte 1C

  # generate 5 addresses
  python generate_cheetahcoin_address.py --count 5

  # provide deterministic private key seed (64 hex chars)
  python generate_cheetahcoin_address.py --seed 1f2e... (64 hex chars)

Dependencies:
  pip install ecdsa base58
"""
import os
import argparse
import hashlib
import binascii

try:
    import ecdsa
    import base58
except ImportError:
    raise SystemExit("Missing dependencies. Run: pip install ecdsa base58")

def sha256(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()

def ripemd160(x: bytes) -> bytes:
    h = hashlib.new('ripemd160')
    h.update(x)
    return h.digest()

def privkey_from_seed_hex(seed_hex: str) -> bytes:
    b = bytes.fromhex(seed_hex)
    if len(b) != 32:
        raise ValueError("Seed must be 32 bytes (64 hex chars)")
    return b

def generate_privkey(randomize=True, seed_hex=None) -> bytes:
    if seed_hex:
        return privkey_from_seed_hex(seed_hex)
    if randomize:
        return os.urandom(32)
    raise ValueError("Either randomize must be True or a seed must be provided")

def pubkey_compressed_from_privkey(privkey_bytes: bytes) -> bytes:
    sk = ecdsa.SigningKey.from_string(privkey_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    raw = vk.to_string()  # 64 bytes: X(32) || Y(32)
    x = raw[:32]
    y = raw[32:]
    prefix = b'\x02' if (y[-1] % 2 == 0) else b'\x03'
    return prefix + x

def hash160(pubkey_bytes: bytes) -> bytes:
    return ripemd160(sha256(pubkey_bytes))

def base58_check_encode(payload: bytes) -> str:
    checksum = sha256(sha256(payload))[:4]
    return base58.b58encode(payload + checksum).decode()

def p2pkh_address_from_pubkey(pubkey_bytes: bytes, version_byte_hex: str) -> str:
    version = bytes.fromhex(version_byte_hex)
    h160 = hash160(pubkey_bytes)
    payload = version + h160
    return base58_check_encode(payload)

def wif_from_privkey(privkey_bytes: bytes, wif_prefix_hex: str, compressed=True) -> str:
    prefix = bytes.fromhex(wif_prefix_hex)
    payload = prefix + privkey_bytes + (b'\x01' if compressed else b'')
    return base58_check_encode(payload)

def main():
    parser = argparse.ArgumentParser(description="Generate CheetahCoin P2PKH address + WIF")
    parser.add_argument("--version-byte", "-v", default="00",
                        help="Address version byte in hex (default: 00). Example: 1C")
    parser.add_argument("--wif-prefix", "-w", default="80",
                        help="WIF prefix byte in hex (default: 80). Example: 9E")
    parser.add_argument("--count", "-n", type=int, default=1, help="How many addresses to generate")
    parser.add_argument("--seed", "-s", default=None, help="Deterministic 32-byte seed (64 hex chars)")
    parser.add_argument("--no-compressed", action="store_true", help="Generate uncompressed pubkey / WIF (not recommended)")
    args = parser.parse_args()

    # Validate hex inputs
    try:
        _ = bytes.fromhex(args.version_byte)
        _ = bytes.fromhex(args.wif_prefix)
    except Exception as e:
        raise SystemExit("version-byte and wif-prefix must be valid hex bytes (e.g. 00 or 1C)")

    compressed = not args.no_compressed

    for i in range(args.count):
        priv = generate_privkey(randomize=(args.seed is None), seed_hex=args.seed)
        pub_compressed = pubkey_compressed_from_privkey(priv) if compressed else None

        address = p2pkh_address_from_pubkey(pub_compressed if compressed else
                                           (ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1)
                                            .get_verifying_key().to_string() ), args.version_byte)

        wif = wif_from_privkey(priv, args.wif_prefix, compressed=compressed)

        print("=== Address #{} ===".format(i+1))
        print("Address:      ", address)
        print("WIF (secret): ", wif)
        print("PrivKey hex:  ", priv.hex())
        if compressed:
            print("Pubkey comp:  ", pub_compressed.hex())
        else:
            vk = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1).get_verifying_key().to_string()
            print("Pubkey uncmp: ", vk.hex())
        print()

if __name__ == "__main__":
    main()