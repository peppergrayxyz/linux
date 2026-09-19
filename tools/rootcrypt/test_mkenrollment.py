#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Test the enrollment ABI and actual OpenSSL signatures without a TPM."""

import pathlib
import shutil
import struct
import subprocess
import tempfile
import unittest
import uuid

import mkenrollment

PARTUUID = "12345678-1234-5678-90ab-cdef12345678"


class EnrollmentTests(unittest.TestCase):
    def test_wire_format(self):
        data = mkenrollment.enrollment_data(PARTUUID, "4,7,9", "30020100")
        self.assertEqual(len(data), 44)
        self.assertEqual(data[:8], b"DMROOTK\0")
        self.assertEqual(struct.unpack_from("<II", data, 8), (1, 0x290))
        self.assertEqual(data[16:32], uuid.UUID(PARTUUID).bytes)
        self.assertEqual(struct.unpack_from("<II", data, 32), (4, 0))
        self.assertEqual(data[40:], bytes.fromhex("30020100"))

    def test_invalid_inputs(self):
        for pcrs in ("", "-1", "24", "7,7", "sha256:7", "7,"):
            with self.subTest(pcrs=pcrs), self.assertRaises(ValueError):
                mkenrollment.enrollment_data(PARTUUID, pcrs, "30020100")
        for blob in ("", "0", "zz", "0001", "30" + "00" * 512):
            with self.subTest(blob=blob[:10]), self.assertRaises(ValueError):
                mkenrollment.enrollment_data(PARTUUID, "7", blob)
        with self.assertRaises(ValueError):
            mkenrollment.enrollment_data("not-a-uuid", "7", "30020100")

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required")
    def test_signature_and_tampering(self):
        with tempfile.TemporaryDirectory(prefix="rootcrypt-test-") as directory:
            directory = pathlib.Path(directory)
            certificate, key = directory / "cert.pem", directory / "key.pem"
            subprocess.run([
                "openssl", "req", "-new", "-x509", "-newkey", "rsa:2048",
                "-nodes", "-subj", "/CN=rootcrypt-test/", "-days", "1",
                "-keyout", str(key), "-out", str(certificate),
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            data = mkenrollment.enrollment_data(PARTUUID, "4,7,9", "30020100")
            record = mkenrollment.sign_record(data, certificate, key)
            content, signature = directory / "data", directory / "signature"
            content.write_bytes(data)
            signature.write_bytes(record[len(data):])
            # VERIFYING_FIRMWARE_SIGNATURE requires authenticated attributes.
            details = subprocess.check_output([
                "openssl", "cms", "-cmsout", "-print", "-inform", "DER",
                "-in", str(signature),
            ], text=True)
            self.assertIn("object: contentType", details)
            self.assertIn("object: messageDigest", details)
            command = [
                "openssl", "cms", "-verify", "-binary", "-inform", "DER",
                "-in", str(signature), "-content", str(content),
                "-CAfile", str(certificate), "-out", str(directory / "verified"),
            ]
            result = subprocess.run(command, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            # Every security-relevant region is covered by the signature.
            for offset in (8, 12, 16, 32, 36, 40):
                changed = bytearray(data)
                changed[offset] ^= 1
                content.write_bytes(changed)
                with self.subTest(offset=offset):
                    result = subprocess.run(command, capture_output=True)
                    self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
