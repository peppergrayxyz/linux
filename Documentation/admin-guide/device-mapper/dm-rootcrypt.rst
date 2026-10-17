.. SPDX-License-Identifier: GPL-2.0

======================================
TPM2 root activation without initramfs
======================================

``CONFIG_DM_CRYPT_ROOT`` activates one plain dm-crypt root partition before
mounting root. It loads a signed enrollment from an EFI variable, unseals a
native Linux trusted-key blob using TPM2 PolicyPCR, and creates ``/dev/dm-0``.
The kernel does not run a userspace helper during activation.

Version 1 uses AES-256-XTS (``aes-xts-plain64``), a 64-byte volume key,
512-byte encryption sectors, IV offset zero, and payload offset zero. The
mapping covers the entire partition. The filesystem is directly inside this
mapping. This is a plain dm-crypt format, not a LUKS volume.

Configuration
=============

Build in EFI support (including ``CONFIG_EFI_STUB`` for direct EFI boot), the
TPM2 transport, storage controller, GPT partition parser, root filesystem,
device mapper, dm-crypt and TPM-backed trusted keys. Enable
``CONFIG_DM_CRYPT_ROOT`` and disable ``CONFIG_BLK_DEV_INITRD``. The option selects
AES-XTS, SHA-256 signature hashing and TPM HMAC/encrypted transactions. It
requires ``CONFIG_SYSTEM_DATA_VERIFICATION``, which has no prompt of its own;
it is enabled, for example, by ``CONFIG_MODULE_SIG``.

Use an RSA/SHA-256 enrollment signing key. Include its X.509 certificate using
``CONFIG_SYSTEM_TRUSTED_KEYS``. All certificates in the built-in trusted
keyring are authorized to sign enrollments; secondary and platform keyrings
are not consulted. This includes the module signing certificate when
``CONFIG_MODULE_SIG`` is enabled, so whoever holds the module signing key can
also sign enrollments. Keep that built-in trust set under the owner's control.

The boot parameters are::

  rootcrypt=PARTUUID=12345678-1234-5678-90ab-cdef12345678
  rootcrypt.key=tpm2 rootcrypt.tpm=0 rootcrypt.token=0
  root=/dev/dm-0 rootfstype=ext4 ro

Put these on one command line. ``rootcrypt=`` accepts a canonical GPT UUID;
``rootcrypt.key=tpm2`` is mandatory. The TPM and token selectors default to
zero, and version 1 accepts only zero. Duplicate or malformed options cause
activation to fail. ``trusted.source=tpm`` is also needed if another trusted
key backend would otherwise be selected.

The coordinator runs in ``prepare_namespace()``, after initcalls. It waits up
to 30 seconds for the partition and TPM2 chip 0, retries trusted-key backend
initialization if its initial attempt preceded TPM probing, then creates
minor 0. Devices created through ``dm-mod.create=`` exist earlier and take minor
0 unless they are given another minor, so give each of them an explicit
nonzero minor. On any activation error the kernel logs the failed step with a
``rootcrypt:`` prefix and panics; it does not fall back to an unencrypted
root. ``rootwait`` does not extend this coordinator's device timeout.

Enrollment format
=================

The variable name is ``LinuxRootKey-<lowercase-PARTUUID>-0``. Its vendor GUID is
``572e6a16-7a6b-4c2f-9e78-41a37c05290b``. Provision it with the nonvolatile,
boot-service and runtime-access attributes. The firmware must support EFI
runtime variable reads.

The variable payload is at most 4096 bytes and consists of:

1. The 40-byte ``struct dm_rootcrypt_record`` from
   ``include/uapi/linux/dm-rootcrypt.h``.
2. ``blob_size`` bytes of the binary native ASN.1 TPM2 trusted-key blob.
3. A detached DER PKCS#7 signature with signed content-type and message-digest
   attributes, covering the header and blob.

The header contains the eight bytes ``DMROOTK\0``, little-endian version 1,
a nonempty 24-bit SHA-256 PCR mask, the partition UUID in RFC 4122 byte order,
the little-endian blob length, and a zero reserved field. Blob length is
limited to 512 bytes. The signature authenticates the partition binding and
PCR selection as well as the sealed blob. This signature provides no
anti-rollback counter.

The blob identifies a persistent TPM storage parent provisioned in advance.
The parent uses empty authorization for loading children. The sealed object
must have a SHA-256 PolicyPCR authorization policy and must not permit
password authorization (``TPMA_OBJECT_USERWITHAUTH`` must be clear). Version
1 does not accept legacy TPM1-style blobs or additional policy assertions.

Provisioning
============

Provision from a trusted maintenance environment. First create a persistent
TPM storage parent, using the TPM administration tools. Record its handle;
do not replace an existing persistent object unintentionally. The following
example assumes a suitable parent already exists at ``0x81000001``.

Calculate the SHA-256 PolicyPCR digest for the desired PCR selection and the
values at the intended root-unseal point. For example, ``tpm2_createpolicy``
can generate ``root.policy`` from a prepared file of expected PCR values::

  tpm2_createpolicy --policy-pcr -l sha256:4,7,9 \
      -f expected-pcrs.bin -L root.policy

The PCR selection is platform-specific. The values from a maintenance boot
will generally differ from the target boot. Bind to measurements identifying
the intended kernel, its effective command line and the Secure Boot state;
Secure Boot policy alone does not uniquely identify an authorized kernel.

Generate a trusted key using the calculated policy digest::

  policy=$(od -An -v -tx1 root.policy | tr -d ' \n')
  key=$(keyctl add trusted rootcrypt \
      "new 64 keyhandle=81000001 hash=sha256 policydigest=$policy" @s)
  keyctl print "$key" > root.blob

The loaded key can be used directly with ``dmsetup`` to create the initial
mapping, without exporting the plaintext volume key. The following command
assumes ``$device`` names the partition being provisioned::

  sectors=$(blockdev --getsz "$device")
  dmsetup create rootcrypt --table \
      "0 $sectors crypt aes-xts-plain64 :64:trusted:rootcrypt 0 $device 0"

Create and install the root filesystem through ``/dev/mapper/rootcrypt``.
Formatting or writing through this device changes the selected partition.

Package the sealed blob with an enrollment signing key whose certificate was
compiled into the target kernel::

  python3 tools/rootcrypt/mkenrollment.py \
      --partuuid 12345678-1234-5678-90ab-cdef12345678 \
      --pcrs 4,7,9 --blob root.blob \
      --certificate enrollment-cert.pem --private-key enrollment-key.pem \
      --efivarfs --output root.efivar

The tool reports the efivarfs filename. ``--efivarfs`` prefixes the four-byte
attributes word required when writing to ``/sys/firmware/efi/efivars``; that
word is not part of the payload returned to the kernel by GetVariable().
Install the generated file as that EFI variable from the maintenance
environment. The tool itself does not modify firmware or the TPM.

Use the native trusted-key interface to check loading when the intended PCR
state is present::

  keyctl add trusted rootcrypt-test \
      "load $(cat root.blob) pcrs=sha256:000290" @s

``000290`` is a hexadecimal mask selecting PCRs 4, 7 and 9. The kernel creates
an unsalted, unbound PolicyPCR session with an empty authorization HMAC, as
allowed for a policy that does not use PolicyAuthValue. An additional salted
HMAC session authenticates Unseal and encrypts its returned key, reusing the
existing TPM session implementation. All temporary sessions are flushed.

The salt is encrypted to the TPM's null primary key, which the kernel cannot
certify at this point. Encryption therefore defeats passive bus snooping, but
an active interposer is only detected afterwards, when userspace certifies the
key name in ``/sys/class/tpm/tpm0/null_name`` (see
Documentation/security/tpm/tpm-security.rst). If that certification fails,
treat the volume key as disclosed.

Boot and key lifetime
=====================

Sign the EFI-stub kernel and authenticate its effective command line. For a
fixed appliance, the architecture's built-in command-line override can keep
the options in the signed image. Enrollment record verification does not by
itself authenticate externally supplied boot options.

Unsealing instantiates a trusted key in a temporary keyring possessed only by
the mapping-creation credentials. dm-crypt copies the key using its normal
trusted-key support. The coordinator revokes its temporary key and drops the
keyring after activation. Plaintext volume-key material remains in kernel
memory for the active dm-crypt device.

Activation does not extend any PCR. Until a selected PCR changes, anything
able to send TPM commands later in the same boot, such as root through
``/dev/tpmrm0``, can repeat PolicyPCR and Unseal to recover the volume key.
To close this window, include a PCR in the selection that early userspace
extends once the root is mounted, and do not select resettable PCRs such as
16 or 23 for production enrollments.

AES-XTS protects confidentiality, not filesystem authenticity. This feature
does not add an authenticated root filesystem. Kernel updates that change
selected PCRs require resealing the same volume key and signing a replacement
enrollment. Preserve an independently protected recovery method; generating
a different volume key does not unlock existing ciphertext.

Testing
=======

``CONFIG_DM_CRYPT_ROOT_KUNIT_TEST`` tests enrollment bounds, versioning, PCR
selection and partition binding. It needs neither firmware nor a TPM; for
example, run it under x86_64 QEMU with this ``kunitconfig`` file::

  CONFIG_KUNIT=y
  CONFIG_PCI=y
  CONFIG_ACPI=y
  CONFIG_EFI=y
  CONFIG_MD=y
  CONFIG_BLK_DEV_DM=y
  CONFIG_DM_CRYPT=y
  CONFIG_KEYS=y
  CONFIG_TCG_TPM=y
  CONFIG_TRUSTED_KEYS=y
  CONFIG_TRUSTED_KEYS_TPM=y
  CONFIG_MODULES=y
  CONFIG_MODULE_SIG=y
  CONFIG_DM_CRYPT_ROOT=y
  CONFIG_DM_CRYPT_ROOT_KUNIT_TEST=y
  # CONFIG_BLK_DEV_INITRD is not set

::

  ./tools/testing/kunit/kunit.py run --arch=x86_64 --kunitconfig=kunitconfig

The packaging and signature tests can run without a TPM::

  python3 tools/rootcrypt/test_mkenrollment.py

QEMU integration tests
----------------------

``tools/rootcrypt/test_qemu.py`` builds a minimal ARM64 kernel and exercises
EFI-stub boot, signed EFI enrollment, TPM2 PolicyPCR unsealing, and mounting
an encrypted ext4 root. ``CONFIG_BLK_DEV_INITRD`` is disabled in the generated
configuration. The suite runs without root privileges, loop devices, host
mounts, host EFI writes, or access to the host TPM.

Install the usual kernel build dependencies, including make, bc, bison, flex
and OpenSSL development headers, plus either GCC/binutils or Clang/LLVM.
The additional requirements are:

* Python 3.9 or newer, the OpenSSL command and shared ``libcrypto``.
* ``qemu-system-aarch64`` with the ``virt`` machine and ``tpm-tis-device``.
* ``swtpm`` with TPM2 support, and ``mke2fs`` from e2fsprogs.
* Matching 64 MiB AAVMF code and blank variable-store images. The default
  paths are ``/usr/share/AAVMF/AAVMF_CODE.fd`` and
  ``/usr/share/AAVMF/AAVMF_VARS.fd``; override them with ``--firmware-code``
  and ``--firmware-vars`` if needed.

The small guest PID 1 is built against the kernel's ``tools/include/nolibc``
and UAPI headers installed from the test kernel build, so no ARM64 C library
or sysroot is needed.

Run from the kernel source tree::

  python3 tools/rootcrypt/test_qemu.py --work-dir /tmp/rootcrypt-qemu

``--compiler gcc`` is the default. The compiler selection applies to both
the kernel and the static guest helper. To run the suite with each compiler,
keep separate work directories::

  python3 tools/rootcrypt/test_qemu.py --compiler gcc \
      --work-dir /tmp/rootcrypt-gcc
  python3 tools/rootcrypt/test_qemu.py --compiler clang \
      --work-dir /tmp/rootcrypt-clang

GCC builds use GCC and GNU binutils. For GCC on a non-ARM64 host, add
``--cross-compile aarch64-linux-gnu-`` (or the appropriate tool prefix).
Clang builds use ``LLVM=1`` for the kernel, including the integrated
assembler, and Clang/LLD with an explicit ARM64 target for the guest.
Clang mode does not require GCC compiler executables or ``--cross-compile``.
The guest links only nolibc, plus ``libgcc`` in GCC mode.

The LLVM tools must be on ``PATH``, or can be selected with ``--llvm`` using
the same convention as Kbuild. For example::

  python3 tools/rootcrypt/test_qemu.py --compiler clang --llvm=-19 \
      --work-dir /tmp/rootcrypt-clang19
  python3 tools/rootcrypt/test_qemu.py --compiler clang --llvm=/opt/llvm/bin/ \
      --work-dir /tmp/rootcrypt-llvm

Use an LLVM version supported by this kernel (see :ref:`kbuild_llvm`). The
same version/path is used for kernel configuration, compilation, host tools,
and the guest compiler/linker. ``--guest-cflags`` accepts additional guest
compile/link flags for either compiler; it does not change kernel flags.

The work directory must be empty on the first run. It receives the generated
signing certificate/private key, kernel build, and a separate artifact
directory for each invocation. Allow several GiB for the kernel build and
retained firmware/disk images. Omit ``--work-dir`` to allocate a new directory
under ``/tmp``. To reuse that suite's certificate and incremental build::

  python3 tools/rootcrypt/test_qemu.py \
      --work-dir /tmp/rootcrypt-qemu --reuse-build

Repeat the same ``--compiler``, ``--llvm`` and guest flags when reusing a
build. Changing compilers in one work directory causes Kbuild to rebuild;
separate work directories preserve both compiler builds.

``--jobs`` controls build parallelism. ``--qemu``, ``--qemu-data``, ``--swtpm``
and ``--mke2fs`` select alternative tool paths. ``--timeout`` sets the limit
per VM boot (120 seconds by default); timeouts and QEMU startup failures are
failures, never successful negative tests. The missing-device cases each
exercise the kernel's 30-second device timeout. QEMU uses software emulation,
so no KVM access is required.

The runner generates fresh TPM state, a persistent storage parent, random
volume keys, and signed enrollment variants. It provisions each enrollment
through efivarfs in a maintenance guest using a copied firmware variable
store. Each boot test gets independent copies of that store and the TPM
state, and a temporary disk overlay. The actual unlock boot receives only
the encrypted GPT disk, except for the explicit plaintext-fallback test.
Neither the maintenance filesystem nor an initramfs supplies early userspace
to the unlock boot.

The happy cases require the TPM/dm-crypt activation message, a successful
ext4 mount on ``dm-0``, and a guest check that ``/`` is backed by the
``rootcrypt`` mapper. PID 1 must also read a fresh random proof string from
the encrypted filesystem. The default TPM/token selectors are tested too.

Negative cases cover:

* Modified signed payloads and signatures, untrusted signers, missing or
  truncated enrollments, wrong partition binding, and an empty PCR mask.
* A key sealed to a different PCR value, a mismatched PCR selection, and an
  object allowing password authorization.
* A valid TPM key that does not decrypt the filesystem.
* Duplicate options, unsupported TPM/token numbers, a missing key-provider
  option, and a malformed partition UUID.
* Rejection when ``root=`` points to an attached, bootable plaintext disk.
* Missing TPM and missing backing partition, including timeout handling.

Enrollment/option rejection cases require the expected rootcrypt panic, the
kernel's ``rootcrypt:`` message for the failed step, and no mapper
activation, root mount, or guest success marker. The wrong-volume-key
case must activate the mapper but fail the filesystem mount. A successful
happy boot is always run first, including when selecting individual cases::

  python3 tools/rootcrypt/test_qemu.py --list
  python3 tools/rootcrypt/test_qemu.py --work-dir /tmp/rootcrypt-qemu \
      --reuse-build --case changed-pcr --case tampered-signature

Results use TAP on stdout and ``results.json`` in the invocation's artifact
directory. ``toolchain.json`` records the compiler selection and guest flags.
Each boot retains its command, serial console and software-TPM log.
The runner terminates its QEMU and software-TPM processes on errors or
interruption.

The AAVMF firmware occasionally stalls while using QEMU's emulated TPM before
it starts the kernel, particularly on loaded hosts. A boot whose kernel has
not started within a third of ``--timeout``, or whose EFI stub reports that the
firmware failed to measure into the TPM, is a firmware failure. Such a boot is
repeated with fresh copies of its variable store and TPM state, up to three
attempts; retries are reported as TAP comments and their logs are kept in
``retry-<n>`` subdirectories. Failures after the kernel has started are never
retried. Exit status is zero for success, one for failure, and four
when required host tools or firmware files are missing.

The firmware template must have Secure Boot disabled for this suite: it
tests enrollment signature enforcement, not the firmware's kernel signature
verification. PCR 16 is a resettable test PCR, not a recommended production
boot policy. Test keys and generated images are disposable fixtures; do not
use them as production enrollments. Physical TPM behavior, firmware Secure
Boot enforcement, and delayed-device arrival require separate platform tests.
