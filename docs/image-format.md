# Firmware image format and recovery

Witcher rebuilds the root filesystem from the hash-pinned
`GTCGR_TITAN4K_V1.6.0P0_R3882-4172-CBRS.prg` vendor input. The kernel and
compressed modem payload are preserved byte for byte. This describes the
build input; it does not require the device to be running 4172 before upload.
See [building](building.md) for the input checksum and toolchain.

## Container

The container has an 84-byte big-endian header, followed by a kernel uImage,
a UBI root filesystem, and a gzip-compressed modem payload called `tk`.

| Header offset | Size | Meaning |
| --- | --- | --- |
| `0x00` | 4 | Magic `0x00007243` |
| `0x04` | 4 | Payload CRC32 |
| `0x08` | 4 | Payload length, excluding header |
| `0x10` | 4 | Vendor software version |
| `0x18` | 4 | Vendor build number |
| `0x24` | 4 | Kernel uImage length |
| `0x28` | 4 | Rootfs UBI length |
| `0x2c` | 4 | Compressed tk length |
| `0x50` | 4 | CRC32 of header bytes `[0, 0x50)` |

Other fields are preserved from the vendor template. Some appear to identify
the device/OEM; their exact meanings are not fully established. CRCs detect
corruption; they do not authenticate a publisher. The unpacker and packer
validate lengths and checksums. Do not recompress the tk payload.

The PRG has no U-Boot or calibration payload. That does not mean flashing is
risk-free: the updater writes NAND and changes bank-selection state.

## Root filesystem metadata

The vendor geometry is 131072-byte physical erase blocks, a VID header at
2048, data at 4096, 126976-byte logical erase blocks, and 2048-byte minimum
I/O. The dynamic volume is named `rootfs`; UBIFS uses LZO compression.

Extraction alone does not preserve everything needed to boot. The build
restores factory permissions after overlay and patch operations, normalizes
new service permissions, and supplies the device nodes from
[`device/dev-nodes.mkfs-D.txt`](../device/dev-nodes.mkfs-D.txt).
The verifier reads metadata from the packed image, checking executable init
and shell targets, startup hooks, directory access, and device identities.
An extracted host directory or a successful CRC check is insufficient.

## Upload and return to stock

Use the desktop firmware page. In Witcher, use **System → Firmware** to
upload a compatible `.prg`. For an intentional downgrade, select the
older-image option. Witcher's updater checks NAND readback and bank selection
before rebooting. Keep power connected throughout the operation.

There are two firmware banks. The boot code itself never switches back, but
the [bank guard](bank-guard.md) does: on the first boot after an update, the
new image must bring up management within 10 minutes, or the guard selects the
old bank and reboots once. It cannot help a kernel that fails before init.
Browser bank switching and recovery require working Linux and networking. `http://DEVICE_IP:8081/` offers password-authenticated recovery
while those services are reachable; it cannot repair a failure before init.
Do not infer that an unresponsive device is safe to power-cycle mid-write.

## Bank selection

NV item 23 in `cmnnv` holds six 36-byte records, two per part (kernel, root
filesystem, modem firmware). Each has the magic `0xcafebabe`, an Adler-32 with
seed 0 over its own bytes 4 to 35, the image size, an Adler-32 of the image as
written, and a sequence number. For each part the bank with the higher
sequence number boots. The updater writes the inactive bank, then raises its
sequence numbers. See [the bank guard](bank-guard.md#how-the-titan-picks-a-bank)
for the full layout and the evidence from the vendor binaries.

## Verification scope

Run the verifier against the exact candidate and its pinned stock input.
CI exercises image metadata, startup and protocol logic, browser flows, and
selected ARM tools under emulation. Hardware qualification must still record
the exact candidate hash, starting firmware, network mode and observed result.
Static verification does not establish bootloader fallback, NAND power-loss
behavior, or compatibility with every Titan model and vendor firmware version.
