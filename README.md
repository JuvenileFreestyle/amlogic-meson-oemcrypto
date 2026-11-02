# amlogic-meson-oemcrypto

Native 64-bit Linux (`aarch64`) Widevine Level 1 (L1) OEMCrypto hardware bridge for Amlogic Meson G12B (S922X/S922Z) SoCs running mainline Linux and LibreELEC.

## Overview

In traditional Linux media player environments, DRM playback is confined to Widevine Level 3 (software decryption), which restricts commercial streaming providers (Netflix, Amazon Prime Video, Disney+) to 720p or 1080p SDR.

`amlogic-meson-oemcrypto` implements Google's standard `OEMCrypto` C API directly on top of Linaro OP-TEE Client (`libteec`) and the Amlogic hardware memory firewall (`amlogic-meson-secmem`), providing bit-accurate hardware decryption into isolated TrustZone memory without CPU exposure.

## Architecture

```
                    [Encrypted Elementary Stream]
                                  │
                                  ▼
                        [inputstream.adaptive]
                                  │
                    Calls OEMCrypto_DecryptCENC()
                                  │
                                  ▼
                     [liboemcrypto_meson.so]
                                  │
      ┌───────────────────────────┴───────────────────────────┐
      │                                                       │
      ▼ (OP-TEE SMC / /dev/tee0)                              ▼ (Allocates /dev/dma_heap/secmem)
[Widevine TA (e043cde0...ta)]                          [SecMem Physical Handle]
      │                                                       │
      └───────────────────────────┬───────────────────────────┘
                                  │ (Decrypted directly in TrustZone)
                                  ▼
                       [Firewalled Secure RAM]
                                  │ (Zero-copy opaque fd)
                                  ▼
                   [Amlogic V4L2 M2M Decoder / amvdec]
                                  │
                                  ▼
                 [Mainline DRM Plane (VD1 Secure Bit)]
                                  │
                                  ▼
                          [HDMI 2.0 Display]
```

## Features

- **Pure Native 64-bit (`aarch64`):** Eliminates 32-bit Android Bionic emulation and `libhybris` dependencies.
- **Direct OP-TEE Communication:** Interacts with Widevine Trusted Application UUID `e043cde0-61d0-11e5-9c26-0002a5d5c51b`.
- **Zero-Copy SecMem Integration:** Direct interface with `/dev/dma_heap/secmem` for TrustZone memory isolation.
- **Standard API Support:** Implements OEMCrypto v16 specification functions.

## Building

Requires `libteec` development headers (`optee_client`):

```bash
make
sudo make install
```

## Authors & License

Developed by `JuvenileFreestyle <JuvenileFreestyle@users.noreply.github.com>`.  
Licensed under the MIT License.
