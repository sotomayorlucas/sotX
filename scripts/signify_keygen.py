#!/usr/bin/env python3
"""
signify_keygen.py -- generate a real Ed25519 signing key for sotBSD.

Writes a 32-byte raw private key to the path given on the command line.
The matching public key is written next to it with a `.pub` suffix
(also raw 32 bytes) so it can be committed to the repo or compared
against `services/init/src/sigkey_generated.rs`.

Use this for **production** signing only. The default dev seed used by
`build_signify_manifest.py` is reproducible from the source tree and
is therefore worthless against an attacker who can read the script.

Workflow
========

  # one-time, on a secure machine:
  python scripts/signify_keygen.py --output ~/.secrets/sotbsd-signify.key

  # subsequent builds:
  SIGNIFY_KEY=~/.secrets/sotbsd-signify.key just sigmanifest
  just image
  # the public key embedded in init now matches the offline private key

The private key file is created with mode 0600. Treat it like an SSH
private key: store it on a hardware token, encrypted volume, or build
server secret store; never commit it to git.

Usage:
    python scripts/signify_keygen.py --output <path>
"""
import argparse
import os
import secrets
import stat
import sys

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("signify-keygen: install `cryptography` first (pip install cryptography)",
          file=sys.stderr)
    sys.exit(2)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", required=True, help="Where to write the private key file")
    ap.add_argument(
        "--force", action="store_true",
        help="Overwrite an existing file (defaults to refusing).",
    )
    args = ap.parse_args()

    if os.path.exists(args.output) and not args.force:
        print(
            f"signify-keygen: refusing to overwrite existing key at {args.output} "
            f"(pass --force if you really mean it)",
            file=sys.stderr,
        )
        return 3

    # Use the OS CSPRNG (32 bytes of true entropy) rather than
    # cryptography's internal randomness, so the failure mode if the
    # CSPRNG is broken is obvious.
    priv_bytes = secrets.token_bytes(32)
    sk = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    pk_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    out_dir = os.path.dirname(os.path.abspath(args.output)) or "."
    os.makedirs(out_dir, exist_ok=True)

    # Write private key with mode 0600 from the start (don't risk a
    # window where the file is world-readable).
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, priv_bytes)
    finally:
        os.close(fd)
    # Belt-and-braces chmod in case umask widened the perms.
    try:
        os.chmod(args.output, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass

    pub_path = args.output + ".pub"
    with open(pub_path, "wb") as f:
        f.write(pk_bytes)

    print(f"signify-keygen: wrote {args.output} (private, mode 0600, 32 bytes)")
    print(f"signify-keygen: wrote {pub_path} (public,  32 bytes)")
    print("signify-keygen: pubkey hex:", pk_bytes.hex())
    print()
    print("Next:")
    print(f"  SIGNIFY_KEY={args.output} just sigmanifest")
    print("  just image")
    return 0


if __name__ == "__main__":
    sys.exit(main())
