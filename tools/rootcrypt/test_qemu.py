#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build and test rootcrypt on ARM64 QEMU virt with disposable EFI and TPM state."""

import argparse
import contextlib
import dataclasses
import json
import os
import re
import secrets
import signal
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import mkenrollment
import qemu_fixtures as fixtures

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[1]
ROOT_OPTIONS = (f"rootcrypt=PARTUUID={fixtures.PARTUUID} rootcrypt.key=tpm2 "
                "rootcrypt.tpm=0 rootcrypt.token=0 root=/dev/dm-0")
COMMON_OPTIONS = ("earlycon=pl011,mmio32,0x9000000 console=ttyAMA0 "
                  "rootfstype=ext4 ro init=/init trusted.source=tpm panic=-1")
REQUIRED_CONFIG = (
    "ACPI", "EFI", "EFI_STUB", "EFI_PARTITION", "EFIVAR_FS", "DM_CRYPT_ROOT",
    "BLK_DEV_DM", "DM_CRYPT", "TRUSTED_KEYS", "TRUSTED_KEYS_TPM", "TCG_TPM",
    "TCG_TIS", "TCG_TPM2_HMAC", "CRYPTO_SHA256", "VIRTIO_MMIO", "VIRTIO_BLK",
    "EXT4_FS", "DEVTMPFS", "DEVTMPFS_MOUNT", "PROC_FS", "SYSFS", "BINFMT_ELF",
    "SERIAL_AMBA_PL011_CONSOLE",
)


@dataclasses.dataclass(frozen=True)
class Toolchain:
    compiler: str
    cross_compile: str = ""
    llvm: str = "1"
    guest_cflags: tuple = ()

    def llvm_tool(self, name):
        if self.llvm.endswith("/"):
            return self.llvm + name
        if self.llvm.startswith("-"):
            return name + self.llvm
        return name

    def programs(self):
        if self.compiler == "gcc":
            return ("gcc", f"{self.cross_compile}gcc")
        return tuple(self.llvm_tool(name) for name in (
            "clang", "clang++", "ld.lld", "llvm-ar", "llvm-nm", "llvm-objcopy",
            "llvm-objdump", "llvm-readelf", "llvm-strip", "llvm-link"))

    def make_args(self):
        common = [f"CROSS_COMPILE={self.cross_compile}"]
        if self.compiler == "gcc":
            return common + ["LLVM=", f"CC={self.cross_compile}gcc", "HOSTCC=gcc"]
        return common + [f"LLVM={self.llvm}", "LLVM_IAS=1",
                         f"CC={self.llvm_tool('clang')}",
                         f"HOSTCC={self.llvm_tool('clang')}"]

    def guest_command(self, headers, output, source):
        if self.compiler == "gcc":
            command, libraries = [f"{self.cross_compile}gcc"], ["-lgcc"]
        else:
            # ARCH selects the kernel target; the userspace helper needs its own
            # target and the same LLD, including when LLVM has a version suffix.
            linker = shutil.which(self.llvm_tool("ld.lld"))
            if not linker:
                raise Failure("the selected LLVM linker is missing")
            command = [self.llvm_tool("clang"), "--target=aarch64-linux-gnu",
                       f"--ld-path={os.path.abspath(linker)}"]
            libraries = []
        # nolibc and the installed UAPI headers replace a target C library.
        return command + [
            "-nostdlib", "-nostdinc", "-ffreestanding", "-static",
            "-Os", "-Wall", "-Wextra", "-Werror",
            f"-I{SOURCE / 'tools/include/nolibc'}", f"-I{headers / 'include'}",
            *self.guest_cflags, "-o", str(output), str(source), *libraries]


@dataclasses.dataclass(frozen=True)
class Case:
    name: str
    record: str = "valid"
    options: str = ROOT_OPTIONS
    error: str = ""
    witnesses: tuple = ()
    tpm: bool = True
    plain_fallback: bool = False
    mount_failure: bool = False


SIGNATURE_FAILED = "rootcrypt: enrollment signature verification failed"
UNSEAL_FAILED = "rootcrypt: cannot unseal the volume key"
TIMED_OUT = "rootcrypt: timed out waiting for backing partition or TPM2 chip 0"

CASES = (
    Case("happy"),
    Case("default-selectors", options=(f"rootcrypt=PARTUUID={fixtures.PARTUUID} "
                                       "rootcrypt.key=tpm2 root=/dev/dm-0")),
    Case("tampered-payload", record="tampered-payload", error="-129",
         witnesses=("Message digest doesn't match", SIGNATURE_FAILED)),
    # RSA padding failure can be EINVAL or EKEYREJECTED, depending on the provider.
    Case("tampered-signature", record="tampered-signature", error="(?:-22|-129)",
         witnesses=(SIGNATURE_FAILED,)),
    Case("untrusted-signer", record="untrusted", error="-126",
         witnesses=(SIGNATURE_FAILED,)),
    Case("missing-enrollment", record="", error="-2",
         witnesses=("rootcrypt: cannot read enrollment EFI variable "
                    f"LinuxRootKey-{fixtures.PARTUUID}-0 (-2)",)),
    Case("truncated-enrollment", record="truncated", error="-22",
         witnesses=("rootcrypt: malformed or unsupported enrollment record",)),
    Case("wrong-partition-binding", record="wrong-partition", error="-129",
         witnesses=("rootcrypt: the enrollment is bound to a different partition",)),
    Case("zero-pcr-mask", record="zero-pcr-mask", error="-22",
         witnesses=("rootcrypt: malformed or unsupported enrollment record",)),
    Case("changed-pcr", record="changed-pcr", error="-1",
         witnesses=("occurred unsealing", UNSEAL_FAILED)),
    Case("wrong-pcr-selection", record="wrong-selection", error="-1",
         witnesses=("occurred unsealing", UNSEAL_FAILED)),
    Case("password-authorized-object", record="password", error="-22",
         witnesses=("key_unseal failed", UNSEAL_FAILED)),
    Case("wrong-volume-key", record="wrong-key", mount_failure=True),
    Case("duplicate-option", options=ROOT_OPTIONS + " rootcrypt.key=tpm2", error="-22",
         witnesses=("rootcrypt: duplicate rootcrypt.key= option",)),
    Case("unsupported-tpm", options=ROOT_OPTIONS.replace("tpm=0", "tpm=1"), error="-22",
         witnesses=("rootcrypt: unsupported rootcrypt.tpm=1",)),
    Case("unsupported-token", options=ROOT_OPTIONS.replace("token=0", "token=1"), error="-22",
         witnesses=("rootcrypt: unsupported rootcrypt.token=1",)),
    Case("missing-key-option", options=ROOT_OPTIONS.replace("rootcrypt.key=tpm2 ", ""),
         error="-22", witnesses=("are required",)),
    Case("malformed-partuuid", options=ROOT_OPTIONS.replace(fixtures.PARTUUID, "bad-uuid"),
         error="-22", witnesses=("rootcrypt: unsupported rootcrypt=PARTUUID=bad-uuid",)),
    Case("no-plaintext-fallback", options=ROOT_OPTIONS.replace(
        "root=/dev/dm-0", f"root=PARTUUID={fixtures.PLAINTEXT_UUID}"),
         error="-22", plain_fallback=True,
         witnesses=("rootcrypt: root=/dev/dm-0 is required",)),
    Case("missing-tpm", error="-110", tpm=False, witnesses=(TIMED_OUT,)),
    Case("missing-partition", error="-110",
         options=ROOT_OPTIONS.replace(fixtures.PARTUUID, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
         witnesses=(TIMED_OUT,)),
)


class Failure(RuntimeError):
    pass


class FirmwareFailure(Failure):
    """The firmware failed before the kernel under test could be judged."""


BOOT_ATTEMPTS = 3
KERNEL_STARTED = "Booting Linux on physical CPU"
FIRMWARE_TPM_FAILURE = "EFI stub: WARNING: Failed to measure"


def stop(process):
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def run_logged(command, log, timeout=None, env=None):
    with log.open("w") as output:
        output.write(shlex.join(map(str, command)) + "\n")
        output.flush()
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT, env=env,
                                   start_new_session=True)
        try:
            rc = process.wait(timeout=timeout)
            if rc:
                raise Failure(f"command exited {rc}; see {log}")
        except subprocess.TimeoutExpired as error:
            raise Failure(f"command timed out after {timeout}s; see {log}") from error
        finally:
            # Also runs on Ctrl-C, including during a build or VM boot.
            stop(process)


def run_vm(command, log, timeout):
    """Run QEMU like run_logged(), reporting firmware failures separately."""
    # AAVMF occasionally stalls on QEMU's TPM before reaching the kernel.
    firmware_timeout = timeout / 3
    started = timed_out = False
    with log.open("w") as output:
        output.write(shlex.join(map(str, command)) + "\n")
        output.flush()
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        begin = time.monotonic()
        try:
            while process.poll() is None:
                elapsed = time.monotonic() - begin
                if elapsed >= timeout:
                    timed_out = True
                    break
                if not started:
                    started = KERNEL_STARTED in log.read_text(errors="replace")
                    if not started and elapsed >= firmware_timeout:
                        raise FirmwareFailure("firmware did not start the kernel within "
                                              f"{firmware_timeout:.0f}s; see {log}")
                time.sleep(0.1)
        finally:
            stop(process)
    text = log.read_text(errors="replace")
    if FIRMWARE_TPM_FAILURE in text:
        raise FirmwareFailure(f"firmware could not use the software TPM; see {log}")
    if timed_out:
        raise Failure(f"command timed out after {timeout}s; see {log}")
    if process.returncode:
        raise Failure(f"command exited {process.returncode}; see {log}")
    return text


def certificate(prefix, log):
    run_logged(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-sha256", "-days", "3650", "-subj", "/CN=rootcrypt-qemu-test/",
                "-keyout", str(prefix.with_suffix(".key")),
                "-out", str(prefix.with_suffix(".pem"))], log, timeout=30)
    prefix.with_suffix(".key").chmod(0o600)


def require(text, needle, log):
    if needle not in text:
        raise Failure(f"missing {needle!r}; see {log}")


class Suite:
    def __init__(self, args):
        self.args = args
        self.toolchain = Toolchain(args.compiler, args.cross_compile, args.llvm,
                                   tuple(args.guest_cflags))
        self.work = args.work_dir
        marker = self.work / ".rootcrypt-qemu"
        identity = {"version": 1, "source": str(SOURCE)}
        if args.reuse_build:
            if not marker.is_file() or json.loads(marker.read_text()) != identity:
                raise Failure("--reuse-build requires this suite's existing work directory")
        else:
            # Never replace another run's artifacts or an unrelated build tree.
            self.work.mkdir(parents=True, exist_ok=True)
            if any(self.work.iterdir()):
                raise Failure("work directory must be empty (or use --reuse-build)")
            self.work.chmod(0o700)
            marker.write_text(json.dumps(identity) + "\n")
        self.run = Path(tempfile.mkdtemp(prefix="run-", dir=self.work))
        self.build = self.work / "build"
        self.signer = self.work / "enrollment"
        self.proof = secrets.token_hex(32)
        print(f"# Artifacts: {self.run}", flush=True)

    def build_kernel(self):
        if not self.args.reuse_build:
            certificate(self.signer, self.work / "certificate.log")
        elif not all(self.signer.with_suffix(suffix).is_file() for suffix in (".key", ".pem")):
            raise Failure("reusable build is missing its enrollment signing key/certificate")
        fragment = self.work / "kernel.config"
        fragment.write_text((HERE / "qemu.config").read_text() +
                            f'CONFIG_SYSTEM_TRUSTED_KEYS="{self.signer}.pem"\n')
        command = ["make", "-C", str(SOURCE), f"O={self.build}", "ARCH=arm64",
                   "KCONFIG_CONFIG=.config"] + self.toolchain.make_args()
        (self.run / "toolchain.json").write_text(
            json.dumps(dataclasses.asdict(self.toolchain), indent=2) + "\n")
        env = os.environ.copy()
        env["KCONFIG_ALLCONFIG"] = str(fragment)
        print(f"# Building the no-initramfs ARM64 test kernel with {self.args.compiler}",
              flush=True)
        run_logged(command + ["allnoconfig"], self.run / "config.log", timeout=120, env=env)
        config = (self.build / ".config").read_text()
        for option in REQUIRED_CONFIG:
            require(config, f"CONFIG_{option}=y\n", self.run / "config.log")
        require(config, "# CONFIG_BLK_DEV_INITRD is not set\n", self.run / "config.log")
        compiler = "GCC" if self.args.compiler == "gcc" else "CLANG"
        require(config, f"CONFIG_CC_IS_{compiler}=y\n", self.run / "config.log")
        env.pop("KCONFIG_ALLCONFIG")
        run_logged(command + [f"-j{self.args.jobs}", "Image"], self.run / "build.log", env=env)
        self.kernel = self.build / "arch/arm64/boot/Image"

    @contextlib.contextmanager
    def swtpm(self, state, log, provisioning=False):
        # Short paths avoid AF_UNIX's path length limit even in deep work trees.
        with tempfile.TemporaryDirectory(prefix="rootcrypt-tpm-") as directory:
            sockets = Path(directory)
            state.mkdir(exist_ok=True)
            command = [self.args.swtpm, "socket", "--tpm2", "--tpmstate", f"dir={state}",
                       "--ctrl", f"type=unixio,path={sockets}/ctrl",
                       "--flags", "not-need-init,startup-clear", "--log", "fd=1,level=20"]
            ready = sockets / "ctrl"
            if provisioning:
                command += ["--server", f"type=unixio,path={sockets}/data"]
                ready = sockets / "data"
            with log.open("w") as output:
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                           stdout=output, stderr=subprocess.STDOUT,
                                           start_new_session=True)
                try:
                    deadline = time.monotonic() + 10
                    while not ready.exists():
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise Failure(f"software TPM failed to start; see {log}")
                        time.sleep(0.02)
                    yield sockets
                finally:
                    stop(process)

    def filesystem(self, directory, image, log):
        with image.open("wb") as output:
            output.truncate(32 * 1024 * 1024)
        run_logged([self.args.mke2fs, "-q", "-F", "-t", "ext4", "-b", "4096",
                    "-O", "^metadata_csum_seed,^orphan_file", "-d", str(directory), str(image)],
                   log, timeout=60)

    def fixtures(self):
        untrusted = self.run / "untrusted"
        certificate(untrusted, self.run / "untrusted-certificate.log")
        volume_key, wrong_key = secrets.token_bytes(64), secrets.token_bytes(64)
        state = self.run / "tpm-base"
        with self.swtpm(state, self.run / "tpm-provision.log", provisioning=True) as sockets:
            blobs = fixtures.provision_tpm(sockets / "data", volume_key, wrong_key)

        def data(blob="valid", pcrs="16", partuuid=fixtures.PARTUUID):
            return mkenrollment.enrollment_data(partuuid, pcrs, blobs[blob].hex())

        def sign(payload, signer=self.signer):
            return mkenrollment.sign_record(payload, signer.with_suffix(".pem"),
                                           signer.with_suffix(".key"))

        records = {name: sign(data(name)) for name in blobs}
        records["wrong-selection"] = sign(data(pcrs="17"))
        records["untrusted"] = sign(data(), untrusted)
        records["wrong-partition"] = sign(data(partuuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"))
        zero_mask = bytearray(data())
        zero_mask[12:16] = bytes(4)
        records["zero-pcr-mask"] = sign(bytes(zero_mask))
        # Keep the envelope structurally valid so verification checks coverage.
        tampered = bytearray(records["valid"])
        tampered[12] ^= 1
        records["tampered-payload"] = bytes(tampered)
        tampered = bytearray(records["valid"])
        tampered[-1] ^= 1
        records["tampered-signature"] = bytes(tampered)
        records["truncated"] = data()  # Complete header/blob but no signature.

        root = self.run / "root-tree"
        for directory in (root, root / "dev", root / "proc", root / "sys"):
            directory.mkdir()
        headers = self.run / "guest-headers"
        run_logged(["make", "-C", str(SOURCE), f"O={self.build}", "ARCH=arm64",
                    *self.toolchain.make_args(), "headers_install",
                    f"INSTALL_HDR_PATH={headers}"],
                   self.run / "guest-headers.log", timeout=300)
        run_logged(self.toolchain.guest_command(headers, root / "init", HERE / "qemu-init.c"),
                   self.run / "guest-build.log", timeout=60)
        (root / "proof").write_text(self.proof)
        self.plain = self.run / "root.ext4"
        self.filesystem(root, self.plain, self.run / "root-mkfs.log")
        self.encrypted = self.run / "encrypted.img"
        fixtures.gpt_disk(self.plain, self.encrypted, volume_key)
        self.fallback = self.run / "plaintext.img"
        fixtures.gpt_disk(self.plain, self.fallback, partuuid=fixtures.PLAINTEXT_UUID)

        # The encrypted root does not contain enrollment/provisioning fixtures.
        (root / "records").mkdir()
        for name, record in records.items():
            (root / "records" / name).write_bytes(b"\x07\0\0\0" + record)
        (root / "variable-name").write_text(
            f"LinuxRootKey-{fixtures.PARTUUID}-0-{mkenrollment.EFI_GUID}")
        self.provision_disk = self.run / "provision.ext4"
        self.filesystem(root, self.provision_disk, self.run / "provision-mkfs.log")

    def boot(self, directory, variables, disk, options, tpm=True, fallback=False):
        log = directory / "console.log"
        command = [self.args.qemu, "-machine", "virt", "-accel", "tcg", "-cpu", "cortex-a57",
                   "-m", "768", "-display", "none", "-serial", "stdio", "-monitor", "none",
                   "-no-reboot", "-net", "none", "-kernel", str(self.kernel),
                   "-drive", f"if=pflash,format=raw,readonly=on,file={self.args.firmware_code}",
                   "-drive", f"if=pflash,format=raw,file={variables}",
                   "-append", COMMON_OPTIONS + " " + options,
                   "-drive", f"file={disk},format=raw,if=none,id=root,snapshot=on",
                   "-device", "virtio-blk-device,drive=root"]
        if self.args.qemu_data:
            command += ["-L", str(self.args.qemu_data)]
        if fallback:
            command += ["-drive", f"file={self.fallback},format=raw,if=none,id=plain,readonly=on",
                        "-device", "virtio-blk-device,drive=plain"]
        if tpm:
            state = directory / "tpm"
            shutil.copytree(self.run / "tpm-base", state)
            with self.swtpm(state, directory / "swtpm.log") as sockets:
                command += ["-chardev", f"socket,id=chrtpm,path={sockets}/ctrl",
                            "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
                            "-device", "tpm-tis-device,tpmdev=tpm0"]
                return run_vm(command, log, self.args.timeout), log
        return run_vm(command, log, self.args.timeout), log

    def boot_retrying(self, directory, variables, *args, **kwargs):
        """Boot from fresh copies of all state, retrying only firmware failures."""
        for attempt in range(1, BOOT_ATTEMPTS + 1):
            target = directory / f"retry-{attempt - 1}" if attempt > 1 else directory
            target.mkdir(exist_ok=True)
            shutil.copyfile(variables, target / "vars.fd")
            try:
                return (*self.boot(target, target / "vars.fd", *args, **kwargs),
                        target / "vars.fd")
            except FirmwareFailure as error:
                if attempt == BOOT_ATTEMPTS:
                    raise
                print(f"# retrying {directory.name}: {error}", flush=True)

    def enroll(self, record):
        directory = self.run / ("enroll-" + (record or "missing"))
        directory.mkdir()
        # An empty record still boots once, so every test starts from a store
        # the firmware has already initialized.
        text, log, variables = self.boot_retrying(
            directory, self.args.firmware_vars, self.provision_disk,
            f"root=/dev/vda rootcrypt_test.record={record}", tpm=False)
        require(text, f"ROOTCRYPT_PROVISIONED: {record or 'none'}", log)
        if "ROOTCRYPT_TEST_FAIL" in text or "Kernel panic" in text:
            raise Failure(f"EFI provisioning failed; see {log}")
        return variables

    def test(self, case, enrollments):
        directory = self.run / case.name
        directory.mkdir()
        if case.record not in enrollments:
            enrollments[case.record] = self.enroll(case.record)
        text, log, _ = self.boot_retrying(directory, enrollments[case.record], self.encrypted,
                                          case.options, tpm=case.tpm,
                                          fallback=case.plain_fallback)
        require(text, "efi: EFI v", log)
        partitions = re.findall(r"^ (?P<disk>vd[a-z]): (?P=disk)1\s*$", text, re.MULTILINE)
        expected = 2 if case.plain_fallback else 1
        if len(partitions) != expected:
            raise Failure(f"expected {expected} GPT disks; see {log}")
        if case.tpm:
            require(text, "2.0 TPM", log)
        for witness in case.witnesses:
            require(text, witness, log)
        if "ROOTCRYPT_TEST_FAIL" in text or re.search(r"^(?:WARNING|BUG):", text, re.MULTILINE):
            raise Failure(f"guest reported a test failure or kernel warning; see {log}")
        if case.error:
            pattern = (r"Kernel panic - not syncing: rootcrypt: cannot activate encrypted root \(" +
                       case.error + r"\)")
            if not re.search(pattern, text):
                raise Failure(f"expected rootcrypt error {case.error}; see {log}")
            for unexpected in ("TPM2 root mapping ready", "Mounted root (", "ROOTCRYPT_BOOT_OK"):
                if unexpected in text:
                    raise Failure(f"unexpected {unexpected!r} after rejected enrollment; see {log}")
        elif case.mount_failure:
            require(text, "rootcrypt: TPM2 root mapping ready on /dev/dm-0", log)
            require(text, "Kernel panic - not syncing: VFS: Unable to mount root fs", log)
            if "ROOTCRYPT_BOOT_OK" in text or "Mounted root (" in text:
                raise Failure(f"wrong volume key mounted root; see {log}")
        else:
            require(text, "rootcrypt: TPM2 root mapping ready on /dev/dm-0", log)
            require(text, "EXT4-fs (dm-0): mounted filesystem", log)
            require(text, f"ROOTCRYPT_BOOT_OK: {self.proof}", log)
            require(text, "reboot: Power down", log)
            if "Kernel panic" in text:
                raise Failure(f"happy boot panicked; see {log}")


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path,
                        help="empty artifact directory; default: new /tmp directory")
    parser.add_argument("--reuse-build", action="store_true",
                        help="reuse the certificate and incremental kernel build in --work-dir")
    parser.add_argument("--firmware-code", type=Path,
                        default=Path("/usr/share/AAVMF/AAVMF_CODE.fd"))
    parser.add_argument("--firmware-vars", type=Path,
                        default=Path("/usr/share/AAVMF/AAVMF_VARS.fd"),
                        help="blank 64 MiB AAVMF variable template, Secure Boot disabled")
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--qemu-data", type=Path, help="optional QEMU firmware/ROM directory (-L)")
    parser.add_argument("--swtpm", default="swtpm")
    parser.add_argument("--mke2fs", default="mke2fs")
    parser.add_argument("--compiler", choices=("gcc", "clang"), default="gcc",
                        help="compiler for the kernel and guest helper (default: gcc)")
    parser.add_argument("--llvm", help="Clang tool selection: 1, a suffix such as -19, "
                        "or a bin directory ending in / (default: 1)")
    parser.add_argument("--guest-cflags", default="",
                        help="extra guest compile/link flags, e.g. --sysroot=... --gcc-toolchain=...")
    parser.add_argument("--cross-compile", default=os.environ.get("CROSS_COMPILE", ""),
                        help="GCC cross-tool prefix, e.g. aarch64-linux-gnu-; not needed for Clang")
    parser.add_argument("--jobs", type=int, default=min(os.cpu_count() or 1, 32))
    parser.add_argument("--timeout", type=int, default=120,
                        help="seconds per VM boot (default: 120)")
    parser.add_argument("--case", action="append", choices=[case.name for case in CASES],
                        help="run selected cases; the happy positive control always runs first")
    parser.add_argument("--list", action="store_true",
                        help="list cases without building or running")
    args = parser.parse_args()
    if args.llvm is not None and args.compiler != "clang":
        parser.error("--llvm requires --compiler clang")
    args.llvm = args.llvm or "1"
    if args.llvm.endswith("/"):
        args.llvm = str(Path(args.llvm).expanduser().resolve()) + "/"
    elif args.llvm != "1" and not re.fullmatch(r"-[A-Za-z0-9_.-]+", args.llvm):
        parser.error("--llvm must be 1, a tool suffix, or a directory ending in /")
    if any(char.isspace() or char in ',"\\' for char in args.llvm):
        parser.error("--llvm cannot contain whitespace, quotes, backslashes or commas")
    try:
        args.guest_cflags = shlex.split(args.guest_cflags)
    except ValueError as error:
        parser.error(f"invalid --guest-cflags: {error}")
    if args.jobs < 1 or args.timeout < 45:
        parser.error("--jobs must be positive; --timeout must be at least 45 seconds")
    if args.reuse_build and not args.work_dir:
        parser.error("--reuse-build requires --work-dir")
    return args


def main():
    args = arguments()
    if args.list:
        print("\n".join(case.name for case in CASES))
        return 0
    print("TAP version 13", flush=True)
    toolchain = Toolchain(args.compiler, args.cross_compile, args.llvm, tuple(args.guest_cflags))
    programs = ("make", "openssl", "bc", "bison", "flex", args.qemu, args.swtpm, args.mke2fs)
    programs += toolchain.programs()
    missing = [program for program in programs if not shutil.which(program)]
    missing += [str(path) for path in (args.firmware_code, args.firmware_vars)
                if not path.is_file()]
    if missing:
        print("1..0 # SKIP missing dependencies: " + ", ".join(missing))
        return 4
    args.firmware_code = args.firmware_code.resolve()
    args.firmware_vars = args.firmware_vars.resolve()
    args.work_dir = (args.work_dir or Path(tempfile.mkdtemp(prefix="rootcrypt-qemu-"))).resolve()
    # Kbuild and QEMU's comma-separated drive options have pathname restrictions.
    for path in (args.work_dir, args.firmware_code, args.firmware_vars):
        if any(char.isspace() or char in ',"\\' for char in str(path)):
            print(f"Bail out! unsupported whitespace/quote/comma in path: {path}")
            return 1
    selected = [case for case in CASES
                if not args.case or case.name == "happy" or case.name in args.case]
    results = []
    try:
        suite = Suite(args)
        suite.build_kernel()
        suite.fixtures()
        print(f"1..{len(selected)}", flush=True)
        enrollments = {}
        for index, case in enumerate(selected, 1):
            try:
                suite.test(case, enrollments)
            except (Failure, OSError, ValueError) as error:
                results.append({"name": case.name, "passed": False, "error": str(error)})
                print(f"not ok {index} - {case.name}\n# {error}", flush=True)
                # A failed positive control invalidates subsequent negative tests.
                if case.name == "happy":
                    for offset, skipped in enumerate(selected[index:], index + 1):
                        results.append({"name": skipped.name, "skipped": True,
                                        "reason": "happy boot failed"})
                        print(f"ok {offset} - {skipped.name} # SKIP happy boot failed", flush=True)
                    break
            else:
                results.append({"name": case.name, "passed": True})
                print(f"ok {index} - {case.name}", flush=True)
        (suite.run / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        return int(any(result.get("passed") is False for result in results))
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError,
            fixtures.tpm2.ProtocolError, TimeoutError, EOFError) as error:
        print(f"Bail out! {error}", flush=True)
        return 1
    except KeyboardInterrupt:
        print("Bail out! interrupted", flush=True)
        return 130


if __name__ == "__main__":
    sys.exit(main())
