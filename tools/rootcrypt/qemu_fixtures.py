# SPDX-License-Identifier: GPL-2.0-only
"""Disposable TPM blobs and encrypted GPT images for test_qemu.py."""

import ctypes
import ctypes.util
import socket
import struct
import sys
import time
import uuid
import zlib
from pathlib import Path

# Reuse the kernel TPM selftest's command marshalling, never its /dev/tpm client.
SOURCE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SOURCE / "tools/testing/selftests/tpm2"))
import tpm2  # noqa: E402

PARTUUID = "12345678-1234-5678-90ab-cdef12345678"
PLAINTEXT_UUID = "00001111-2222-3333-4444-555566667777"
PARENT = 0x81000001


class SocketTPM(tpm2.Client):
    def __init__(self, path):
        self.tpm = socket.socket(socket.AF_UNIX)
        self.tpm.settimeout(10)
        self.tpm.connect(str(path))

    def read_exact(self, size):
        data = bytearray()
        while len(data) < size:
            chunk = self.tpm.recv(size - len(data))
            if not chunk:
                raise EOFError("software TPM disconnected")
            data.extend(chunk)
        return bytes(data)

    def send_cmd(self, command):
        # TPM_RC_RETRY, TPM_RC_YIELDED and TPM_RC_TESTING are transient.
        for _ in range(100):
            self.tpm.sendall(command)
            header = self.read_exact(10)
            _, size, rc = struct.unpack(">HII", header)
            if not 10 <= size <= 4096:
                raise ValueError(f"invalid software TPM response size {size}")
            response = header + self.read_exact(size - 10)
            if rc in (0x922, 0x908, 0x90a):
                time.sleep(0.02)
                continue
            if rc:
                raise tpm2.ProtocolError(struct.unpack_from(">I", command, 6)[0], rc)
            return response
        raise TimeoutError("software TPM kept returning a retry response")


def der(tag, data):
    length = len(data)
    if length < 128:
        encoded = bytes([length])
    else:
        encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
        encoded = bytes([0x80 | len(encoded)]) + encoded
    return bytes([tag]) + encoded + data


def native_blob(blob):
    """Encode the native Linux TPM2 trusted-key ASN.1 wrapper."""
    private_end = 2 + int.from_bytes(blob[:2], "big")
    public_end = private_end + 2 + int.from_bytes(blob[private_end:private_end + 2], "big")
    if not 4 <= private_end < public_end <= len(blob):
        raise ValueError("invalid TPM2_Create response")
    # TPMSealedData OID, emptyAuth, persistent parent, TPM2B_PUBLIC/PRIVATE.
    return der(0x30, der(6, bytes.fromhex("6781050a0105")) +
               der(0xa0, der(1, b"\xff")) +
               der(2, b"\0" + PARENT.to_bytes(4, "big")) +
               der(4, blob[private_end:public_end]) + der(4, blob[:private_end]))


def pcr_policy(client):
    session = client.start_auth_session(tpm2.TPM2_SE_TRIAL, tpm2.TPM2_ALG_SHA256)
    try:
        client.policy_pcr(session, [16], tpm2.TPM2_ALG_SHA256, tpm2.TPM2_ALG_SHA256)
        return client.get_policy_digest(session)
    finally:
        client.flush_context(session)


def provision_tpm(path, volume_key, wrong_key):
    """Create a persistent parent and four blobs in a fresh software TPM."""
    client = SocketTPM(path)
    try:
        if client.read_pcr(16, tpm2.TPM2_ALG_SHA256) != bytes(32):
            raise ValueError("test TPM did not start with a reset SHA-256 PCR 16")
        parent = client.create_root_key()
        try:
            auth = bytes(tpm2.AuthCommand())
            body = struct.pack(">III", tpm2.TPM2_RH_OWNER, parent, len(auth))
            body += auth + struct.pack(">I", PARENT)
            client.send_cmd(struct.pack(">HII", 0x8002, 10 + len(body), 0x120) + body)
            policy = pcr_policy(client)
            blobs = {
                "valid": native_blob(client.seal(parent, volume_key, b"", policy,
                                                 tpm2.TPM2_ALG_SHA256)),
                "password": native_blob(client.seal(parent, volume_key, b"", None,
                                                    tpm2.TPM2_ALG_SHA256)),
                "wrong-key": native_blob(client.seal(parent, wrong_key, b"", policy,
                                                     tpm2.TPM2_ALG_SHA256)),
            }
            # Seal to an actual different PCR value, keeping the selection fixed.
            # Each QEMU boot resets PCR 16, so this object's policy must fail.
            client.extend_pcr(16, b"\x42" * 32, tpm2.TPM2_ALG_SHA256)
            blobs["changed-pcr"] = native_blob(client.seal(
                parent, volume_key, b"", pcr_policy(client), tpm2.TPM2_ALG_SHA256))
            return blobs
        finally:
            client.flush_context(parent)
    finally:
        client.close()


class XTS:
    """OpenSSL EVP AES-256-XTS, with one 512-byte data unit per call."""
    def __init__(self, key):
        library = ctypes.util.find_library("crypto")
        if not library:
            raise RuntimeError("OpenSSL libcrypto is required for disk encryption")
        self.lib = ctypes.CDLL(library)
        self.lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
        self.lib.EVP_aes_256_xts.restype = ctypes.c_void_p
        self.lib.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                              ctypes.c_void_p, ctypes.c_char_p,
                                              ctypes.c_char_p]
        self.lib.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                             ctypes.c_void_p, ctypes.c_char_p,
                                             ctypes.c_int]
        self.lib.EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                               ctypes.c_void_p]
        self.lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
        self.context = self.lib.EVP_CIPHER_CTX_new()
        self.cipher = self.lib.EVP_aes_256_xts()
        self.key = key
        self.output = ctypes.create_string_buffer(528)
        if not self.context or not self.cipher or len(key) != 64:
            self.close()
            raise RuntimeError("cannot initialize AES-256-XTS")

    def close(self):
        if self.context:
            self.lib.EVP_CIPHER_CTX_free(self.context)
            self.context = None

    def encrypt(self, index, sector):
        count, final = ctypes.c_int(), ctypes.c_int()
        tail = ctypes.create_string_buffer(16)
        if (len(sector) != 512 or
                self.lib.EVP_EncryptInit_ex(self.context, self.cipher, None,
                                           self.key, index.to_bytes(16, "little")) != 1 or
                self.lib.EVP_EncryptUpdate(self.context, self.output,
                                          ctypes.byref(count), sector, 512) != 1 or
                self.lib.EVP_EncryptFinal_ex(self.context, tail,
                                            ctypes.byref(final)) != 1 or
                count.value != 512 or final.value != 0):
            raise RuntimeError(f"AES-XTS encryption failed at sector {index}")
        return self.output.raw[:512]


def gpt_disk(filesystem, output, key=None, partuuid=PARTUUID):
    """Wrap a filesystem in GPT, optionally encrypting its partition with XTS."""
    size = filesystem.stat().st_size
    if size % 512:
        raise ValueError("filesystem image is not sector aligned")
    sectors, start = size // 512, 2048
    total = start + sectors + 2048
    entries = bytearray(128 * 128)
    entries[:128] = struct.pack(
        "<16s16sQQQ72s", uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4").bytes_le,
        uuid.UUID(partuuid).bytes_le, start, start + sectors - 1, 0,
        "rootcrypt-test".encode("utf-16le"))
    disk_uuid = uuid.uuid4().bytes_le

    def header(lba, backup, table):
        data = bytearray(struct.pack(
            "<8sIIIIQQQQ16sQIII", b"EFI PART", 0x10000, 92, 0, 0, lba, backup,
            34, total - 34, disk_uuid, table, 128, 128, zlib.crc32(entries)))
        struct.pack_into("<I", data, 16, zlib.crc32(data))
        return data + bytes(512 - len(data))

    mbr = bytearray(512)
    mbr[446:462] = struct.pack("<B3sB3sII", 0, bytes(3), 0xee, b"\xff" * 3, 1, total - 1)
    mbr[510:] = b"\x55\xaa"
    cipher = XTS(key) if key is not None else None
    try:
        with output.open("wb") as disk, filesystem.open("rb") as source:
            disk.truncate(total * 512)
            disk.write(mbr)
            disk.write(header(1, total - 1, 2))
            disk.write(entries)
            disk.seek(start * 512)
            for index in range(sectors):
                sector = source.read(512)
                disk.write(cipher.encrypt(index, sector) if cipher else sector)
            disk.seek((total - 33) * 512)
            disk.write(entries)
            disk.write(header(total - 1, 1, total - 33))
    finally:
        if cipher:
            cipher.close()
