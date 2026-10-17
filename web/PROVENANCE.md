# UI source provenance

The UI originated in Centreville Tech's Titan operations project and is now
maintained in `web/`. CI rebuilds the device UI from this source and the locked
npm dependencies. Tests and screenshot captures use synthetic fixtures.

The source build covers the UI, first-boot service, network keeper and entropy
collector. Some native services remain pinned binary inputs; see
[building](../docs/building.md) and [component provenance](../THIRD_PARTY.md).
