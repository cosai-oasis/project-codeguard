---
description: Firmware security (UEFI, BIOS, BMC, embedded boot, updates, SMM, DMA, debug interfaces)
languages:
- c
- cpp
- rust
alwaysApply: false
tags:
- infrastructure
---

rule_id: codeguard-0-firmware-security

## Firmware Security (UEFI/EDK II, BIOS, BMC, Embedded)

Secure development of platform and embedded firmware: boot chain integrity, authenticated updates, privileged execution modes (SMM/MM, TrustZone), hardware register and DMA access, debug interfaces, and firmware trust boundaries. Applies to C/C++, Rust, and assembly. Combine with [write-memory-safe-systems-code](write-memory-safe-systems-code.md) for memory-safety and [crypto-algorithms](crypto-algorithms.md) for algorithm selection.

### Threat Model and Trust Boundaries
- Treat every input that crosses into a more privileged context as attacker-controlled: OS-to-SMM/MM communication buffers, UEFI variables, capsule and update images, option ROMs, ACPI/SMBIOS tables supplied by other components, network boot payloads, BMC/host interfaces (IPMI KCS/BT, Redfish host interface, mailboxes), and data read from external flash or removable media.
- Document each boundary (who writes, who reads, at what privilege) and validate at the point of crossing, not later.
- Assume physical attackers for devices in untrusted locations: external flash can be reprogrammed, buses can be probed, and debug ports can be reached.

### Secure Boot
- Establish a hardware root of trust (boot ROM, fused key hash, Boot Guard/PSB, or equivalent); every stage must verify the next stage's signature before executing it. Never fall back to booting unverified code on verification failure. Halt or enter a defined recovery path instead.
- Verify the whole image you execute. Hash and verify after copying into protected memory, then execute only that copy, so the image can't be swapped between check and use.
- UEFI Secure Boot: ship with `PK`, `KEK`, `db`, and `dbx` provisioned; never ship test or vendor-shared "DO NOT TRUST" platform keys; honor `dbx` revocations (SBAT is enforced by shim, not platform firmware); do not expose setup-mode transitions without physical presence or authenticated policy.
- Use SHA-256 or stronger and ECDSA P-256/P-384 or RSA ≥3072 where the platform allows. SHA-1 is not acceptable for signatures or measurements. Where UEFI Authenticode compatibility forces RSA-2048 PKCS#1 v1.5, document it as a constrained exception.
- Keep signing keys in an HSM; separate production and development keys; development-signed images must not boot on production-fused parts.

### Measured Boot
- Measure each component (code, configuration, security-relevant variables, and policy) into the TPM *before* executing or consuming it (`Tcg2Protocol->HashLogExtendEvent`, or the PEI equivalent).
- Use SHA-256 (or stronger) PCR banks; do not rely on the SHA-1 bank alone.
- Keep the event log consistent with PCR extends; never skip a measurement on error paths; extend a separator/error event so failures are visible to attestation.
- Cap PCRs at boundary transitions (e.g., ReadyToBoot/ExitBootServices) so later code cannot forge earlier measurements.

### Authenticated Firmware Updates and Capsules
- Authenticate every update (UEFI capsule, FMP payload, BMC image, peripheral firmware) with a signature verified by firmware already trusted. Use `FmpAuthenticationLib`/`AuthenticateFmpImage` in EDK II rather than custom parsers.
- Enforce anti-rollback: reject images whose version is below `LowestSupportedVersion` or a monotonic counter/fuse value; update the floor only after a successful, verified update.
- Parse capsule headers defensively: validate `HeaderSize`, `CapsuleImageSize`, FMP item offsets, and counts against the actual buffer size with checked arithmetic; reject overlapping or out-of-range offsets; handle scatter-gather lists without trusting OS-provided lengths.
- Verify the image after it lands in protected memory, and verify again (or read back and compare) after writing to flash.
- Use A/B slots or a protected recovery image so a failed or interrupted update can't brick the device; never leave the device booting a partially written image.
- Disable or authenticate vendor-specific "flash tool" SMI handlers and runtime update paths that bypass capsule authentication.

### SMM / Standalone MM and Other Privileged Handlers
- Validate communication buffers before use: confirm the buffer lies entirely outside SMRAM/MMRAM (`SmmIsBufferOutsideSmmValid` / `MmIsBufferOutsideMmValid`), including any nested pointers inside the buffer.
- Copy-then-validate: copy the request into SMRAM once and operate only on the copy to prevent TOCTOU/double-fetch races from other CPUs or DMA.
- Never call out of SMM into boot services, runtime services, or OS-owned function pointers; do not dereference pointers in non-SMRAM memory as code.
- Lock SMRAM (`D_LCK`, TSEG/SMRR) and signal `SmmReadyToLock`/`EndOfDxe` before running any third-party code (option ROMs, shell, OS loaders).
- Register only the SMI handlers required in production; remove debug/test handlers.
- Apply the same rules to TrustZone secure-world services, PSP/ME mailboxes, and hypervisor hypercalls.

```c
EFI_STATUS
EFIAPI
MyMmiHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context,
  IN OUT VOID        *CommBuffer,
  IN OUT UINTN       *CommBufferSize
  )
{
  MY_REQUEST  Request;

  if ((CommBuffer == NULL) || (CommBufferSize == NULL)) {
    return EFI_SUCCESS;
  }

  if ((*CommBufferSize != sizeof (MY_REQUEST)) ||
      !MmIsBufferOutsideMmValid ((EFI_PHYSICAL_ADDRESS)(UINTN)CommBuffer, *CommBufferSize))
  {
    return EFI_SUCCESS;
  }

  // Single fetch into MMRAM; validate and use only the local copy.
  CopyMem (&Request, CommBuffer, sizeof (Request));

  if (Request.Length > MAX_PAYLOAD) {
    return EFI_SUCCESS;
  }

  // ... process Request ...
  return EFI_SUCCESS;
}
```

### UEFI Variables and Configuration
- Treat NV variables as untrusted on read: validate size, type, and range before use; don't assume a variable was written by firmware.
- Use authenticated variables (`EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS`) or `EDKII_VARIABLE_POLICY_PROTOCOL` locks for security-relevant settings; lock before `EndOfDxe`.
- Do not store secrets (passwords, keys) in plain NV variables; store only salted hashes using a slow KDF, or keep them in TPM/secure storage.
- Security-relevant variables that are not boot-service-only must not carry the `EFI_VARIABLE_RUNTIME_ACCESS` attribute unless required and authenticated.

### Hardware Register, MMIO, and Flash Protection
- Access MMIO through `volatile` accessors (`MmioRead32`/`MmioWrite32`, `core::ptr::read_volatile` in Rust) and enforce required ordering with barriers.
- Validate any register address or offset derived from input against a fixed allow-list of device ranges; never allow arbitrary physical address read/write from a less privileged caller.
- Validate PCI BARs and device-reported sizes before mapping; don't let a malicious device remap BARs over SMRAM or firmware regions.
- Set and lock hardware protections before leaving the manufacturer-trusted phase: SPI BIOS write protection (`BLE`, `SMM_BWP`, Protected Range Registers), flash descriptor locks, SMRR/TSEG, memory controller and IOMMU locks, and configuration lock bits. Verify lock state in CI using tools such as CHIPSEC.
- Treat lock-once registers as one-shot: write the final value and set the lock in the same phase; never defer locking to the OS.

### DMA Protection
- Enable the IOMMU (VT-d/AMD-Vi/SMMU) as early as possible (PEI/early boot) and keep it enabled until the OS takes ownership; publish DMAR/IVRS tables correctly so the OS can maintain protection.
- Map only the specific buffers a device needs, for the duration needed; never map SMRAM, firmware code, keys, or page tables for DMA.
- Disable bus mastering on devices not in use, and on all devices at `ExitBootServices` unless the OS requires otherwise.
- Treat Thunderbolt/USB4/PCIe hot-plug devices and option ROMs as untrusted; require signed option ROMs under Secure Boot.

### Debug Interfaces and Manufacturing Mode
- Disable or fuse-lock JTAG, SWD, DCI, UART consoles, and vendor debug mailboxes on production parts; if debug must remain available, require cryptographic authentication (challenge-response with a per-device or per-product key).
- Strip debug builds, verbose `DEBUG()` output, and assertion paths that leak memory contents from production images (`PcdDebugPropertyMask`, release build targets).
- Manufacturing/provisioning mode must be one-way: close it (fuse, OTP, or locked flag) before shipping; firmware must refuse to re-enter it without authenticated authorization; verify end-of-manufacturing state in factory tests.
- Never ship shared default passwords for BIOS setup, BMC, or service accounts; require unique per-device credentials or forced change on first use.

### Firmware IPC and Shared Memory
- For host/BMC, host/ME/PSP, inter-core mailboxes, and shared-memory rings: define fixed message formats with explicit lengths; validate length fields against both the protocol maximum and the actual buffer before reading.
- Copy messages out of shared memory before parsing (no double fetch); use checked arithmetic (`SafeIntLib`: `SafeUintnAdd`, `SafeUint32Mult`) for every size/offset computation.
- Authenticate the peer where the transport allows it; reject commands not permitted in the current boot phase or privilege state.
- BMC: disable IPMI over LAN cipher suite 0 and anonymous/null users; prefer Redfish over HTTPS (TLS 1.3 preferred, 1.2 minimum) with per-device credentials; restrict host-to-BMC interfaces after boot.

### Coding Standards (CERT C, MISRA C, Rust)
- Follow CERT C rules relevant to firmware: INT30/INT32 (integer overflow), ARR30 (bounds), MEM30/MEM31 (use-after-free, leaks), EXP33 (uninitialized reads), STR31 (string termination).
- Apply MISRA C:2012/2023 where required: no dynamic allocation after initialization, no recursion in privileged handlers, explicit fixed-width types, no implicit narrowing, every `switch` has a `default`.
- Zero secrets (keys, passwords, hashes of passwords) with a non-elidable routine (`ZeroMem` followed by a compiler barrier, `explicit_bzero`, or `zeroize` in Rust) before freeing or leaving scope.
- Build with stack protection, NX/W^X memory attributes (`PcdDxeNxMemoryProtectionPolicy`, `PcdImageProtectionPolicy`), and null-page detection where supported.
- Rust: keep `unsafe` confined to small, audited MMIO/FFI wrappers; expose safe APIs above them; deny `unsafe_op_in_unsafe_fn`.
- Assembly: preserve and clear registers holding secrets on mode transitions; validate inputs before entering privileged or secure-world code; avoid speculative-execution gadgets in SMM/secure-world entry paths (apply vendor mitigations).

### Implementation Checklist
- Every boot stage verifies the next; no unverified fallback; production keys only; `dbx`/SBAT honored.
- All components are measured into a SHA-256+ PCR bank before execution; the event log stays consistent.
- Updates are signed, version-floored against rollback, parsed with checked arithmetic, and recoverable.
- SMM/MM handlers validate buffer location, copy before validation, never call out, and SMRAM is locked before third-party code runs.
- Flash, SMRAM, and IOMMU protections are set and locked before `EndOfDxe`; verified with CHIPSEC or equivalent.
- IOMMU is enabled early; DMA mappings are minimal; bus mastering is disabled when not needed.
- Debug ports are fused or authenticated; manufacturing mode is closed; no default credentials.
- IPC and shared-memory messages are length-checked, single-fetched, and allowed only for the current boot phase.
- CERT C/MISRA findings are triaged; secrets are zeroized; NX/stack protections are enabled.
