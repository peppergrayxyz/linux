#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Package a native TPM2 trusted-key blob as a signed rootcrypt EFI record."""

import argparse
import pathlib
import struct
import subprocess
import tempfile
import uuid

EFI_GUID = "572e6a16-7a6b-4c2f-9e78-41a37c05290b"
MAGIC = b"DMROOTK\0"
HEADER = struct.Struct("<8sII16sII")
MAX_BLOB_SIZE = 512
MAX_RECORD_SIZE = 4096


def pcr_mask(value):
    try:
        pcrs = [int(item, 10) for item in value.split(",")]
    except ValueError as error:
        raise ValueError("PCRs must be comma-separated integers") from error
    if not pcrs or any(pcr < 0 or pcr > 23 for pcr in pcrs):
        raise ValueError("select at least one SHA-256 PCR in the range 0..23")
    if len(set(pcrs)) != len(pcrs):
        raise ValueError("duplicate PCR selection")
    return sum(1 << pcr for pcr in pcrs)


def enrollment_data(partuuid, selection, blob_hex):
    partuuid = uuid.UUID(partuuid)
    blob = bytes.fromhex(blob_hex.strip())
    if not 0 < len(blob) <= MAX_BLOB_SIZE:
        raise ValueError("trusted-key blob must contain 1..512 bytes")
    if blob[0] != 0x30:
        raise ValueError("expected a native ASN.1 TPM2 trusted-key blob")
    return HEADER.pack(MAGIC, 1, pcr_mask(selection), partuuid.bytes,
                       len(blob), 0) + blob


def sign_record(data, certificate, private_key):
    with tempfile.TemporaryDirectory(prefix="rootcrypt-") as directory:
        directory = pathlib.Path(directory)
        payload = directory / "record"
        signature = directory / "signature.der"
        payload.write_bytes(data)
        subprocess.run([
            "openssl", "cms", "-sign", "-binary", "-nosmimecap", "-md", "sha256",
            "-in", str(payload), "-signer", str(certificate),
            "-inkey", str(private_key), "-outform", "DER", "-out", str(signature),
        ], check=True)
        record = data + signature.read_bytes()
    if len(record) > MAX_RECORD_SIZE:
        raise ValueError("signed record exceeds the kernel's 4096-byte limit")
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--partuuid", required=True)
    parser.add_argument("--pcrs", required=True, help="SHA-256 indices, e.g. 4,7,9")
    parser.add_argument("--blob", required=True, type=pathlib.Path,
                        help="hexadecimal output of keyctl print for a trusted key")
    parser.add_argument("--certificate", required=True, type=pathlib.Path)
    parser.add_argument("--private-key", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--efivarfs", action="store_true",
                        help="prefix the four-byte efivarfs attributes (NV|BS|RT)")
    args = parser.parse_args()
    try:
        data = enrollment_data(args.partuuid, args.pcrs, args.blob.read_text())
        record = sign_record(data, args.certificate, args.private_key)
        if args.efivarfs:
            record = struct.pack("<I", 7) + record
        # Never replace an existing enrollment silently.
        with args.output.open("xb") as output:
            output.write(record)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"mkenrollment: {error}\n")
    name = f"LinuxRootKey-{uuid.UUID(args.partuuid)}-0-{EFI_GUID}"
    print(f"Created {args.output}; EFI variable filename: {name}")


if __name__ == "__main__":
    main()
