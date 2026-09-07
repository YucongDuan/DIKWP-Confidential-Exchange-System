from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from .identity import generate_identity, load_public_identity
from .dikwp import compile_payload, load_yaml_or_json, load_codebook, validate_payload
from .crypto import encrypt_file, decrypt_file, verify_bundle
from .audit import make_audit_record


def _pass(prompt: str) -> str:
    return getpass.getpass(prompt)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="dce", description="DIKWP Confidential Exchange system")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="generate an identity")
    p.add_argument("--name", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--passphrase")

    p = sub.add_parser("fingerprint", help="print a public identity fingerprint")
    p.add_argument("public_json")

    p = sub.add_parser("compile", help="validate and canonicalize a DIKWP payload")
    p.add_argument("--in", dest="in_path", required=True)
    p.add_argument("--out", dest="out_path", required=True)
    p.add_argument("--codebook")

    p = sub.add_parser("encrypt", help="encrypt a compiled payload for a recipient")
    p.add_argument("--sender-private", required=True)
    p.add_argument("--sender-passphrase")
    p.add_argument("--recipient-public", required=True)
    p.add_argument("--payload", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--purpose", required=True)
    p.add_argument("--fixed-size", type=int, default=16384)

    p = sub.add_parser("verify", help="verify sender signature and envelope header")
    p.add_argument("--bundle", required=True)
    p.add_argument("--sender-public", required=True)

    p = sub.add_parser("decrypt", help="decrypt a bundle")
    p.add_argument("--recipient-private", required=True)
    p.add_argument("--recipient-passphrase")
    p.add_argument("--sender-public", required=True)
    p.add_argument("--bundle", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("audit", help="write a hash-only audit record")
    p.add_argument("--bundle", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--operator", default="local")

    args = parser.parse_args(argv)
    try:
        if args.cmd == "init":
            pw = args.passphrase or _pass("New identity passphrase: ")
            doc = generate_identity(args.name, args.out, pw)
            print(doc["fingerprint"])
        elif args.cmd == "fingerprint":
            print(load_public_identity(args.public_json)["fingerprint"])
        elif args.cmd == "compile":
            doc = compile_payload(args.in_path, args.out_path, args.codebook)
            print(doc["payload_hash_sha256"])
        elif args.cmd == "encrypt":
            pw = args.sender_passphrase or _pass("Sender passphrase: ")
            bundle = encrypt_file(args.sender_private, pw, args.recipient_public, args.payload, args.out, args.purpose, args.fixed_size)
            print(bundle["header"]["payload_sha256"])
        elif args.cmd == "verify":
            print(verify_bundle(args.bundle, args.sender_public))
        elif args.cmd == "decrypt":
            pw = args.recipient_passphrase or _pass("Recipient passphrase: ")
            payload = decrypt_file(args.recipient_private, pw, args.sender_public, args.bundle, args.out)
            print(f"wrote {len(payload)} bytes")
        elif args.cmd == "audit":
            rec = make_audit_record(args.bundle, args.out, args.operator)
            print(rec["audit_record_sha256"])
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
