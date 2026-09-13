# Full-height provider icon placement

Replay the accepted `b3b59f2e0` change: transaction provider confirmation uses the
same validated, centered icon staging helper as provider loading. The old path
started every tall icon at y=6, placing the bottom of a valid 64-pixel icon beyond
the display. The shared helper starts a 64-pixel icon at y=0 and enforces the same
width/height limits as loading.

All 14 existing SignedMetadataIcon native tests passed. This is decoder and
geometry regression evidence; it does not claim physical OLED validation of the
new placement. Preserve the release's required final display evidence.
