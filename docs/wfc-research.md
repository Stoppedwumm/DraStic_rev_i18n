# WFC (Nintendo Wi-Fi Connection) research notes

Target: `universal/lib/arm64-v8a/libdrastic_arm64.so` (r2.6.0.4a, BuildID `2318f180e6c9aca21dd6dc52fb2706ea3855b34a`).
All addresses below are file/virtual offsets in that library (they are identical for this ELF).

## Current state of wireless emulation in DraStic

DraStic has a **minimal stub** for the ARM7 wifi region (`0x04800000`–`0x048FFFFF`).
It is enough for games to boot past wifi init, but nothing is transmitted or received.

| Handler           | Address   | Behaviour |
|-------------------|-----------|-----------|
| wifi read8        | `0x261b8` | returns 0 |
| wifi read16       | `0x261c0` | see below |
| wifi read32       | `0x26274` | returns 0 |
| wifi write8       | `0x24ebc` | ignored   |
| wifi write16      | `0x24ec0` | see below |
| wifi write32      | `0x24f38` | ignored   |

read16 / write16 (`addr` is the offset inside the region):

- `(addr & 0xC000) == 0x4000` → wifi RAM, backed by `state + 0x17070` (index `addr & 0x3FFF`).
- otherwise registers, backed by `state + 0xFB5B8` (index `addr & 0x3FFF`), with special cases:
  - `0x158` W_BB_CNT write: if `(val & 0x3000) == 0x1000`, store byte `state[0xFB712]` (W_BB_WRITE) into
    the baseband register array `state + 0xFB9B8` at `val & 0x7F`.
  - `0x15C` W_BB_READ: if last W_BB_CNT `(state[0xFB710] & 0x7000) == 0x6000`, return `bb[cnt & 0x7F]`, else 0.
  - `0x004`, `0x15E` (W_BB_BUSY), `0x180` (W_RF_BUSY) read as 0.
  - `0x03C` (W_POWERSTATE) reads as `0x0200`.
  - everything else reads back whatever was written.

There are no wifi timers (W_US_COUNT / W_US_COMPARE), no TX/RX state machine, no wifi IRQ,
and the library imports no socket APIs (`socket`, `connect`, `send`, …). The APK also lacks the
`INTERNET` permission.

## Hook point

The per-region memory handlers come from a static table in `.data.rel.ro`
(filled by `R_AARCH64_RELATIVE` relocations, so it is a plain array of pointers at runtime):

```
0x133bb0  ARM7 I/O   read8/16/32   (0x24f3c, 0x25588, 0x25da0)
0x133bc8  ARM7 wifi  read8/16/32   (0x261b8, 0x261c0, 0x26274)
0x133be0  ARM7 wifi  write8/16/32  (0x24ebc, 0x24ec0, 0x24f38)
```

Handler signatures (from the code): `read(void *state, u32 addr)` → `u32`,
`write(void *state, u32 addr, u32 value)`.

The memory-map init routine (around `0x2a1d4`–`0x2a2a8`) copies these triplets into the runtime
memory map (`ldr q, [table]` / `str q, [map + …]`). So a separate injected library can:

1. locate the `libdrastic_arm64.so` base (e.g. `dladdr` on `JNI_OnLoad`),
2. `mprotect` the RELRO page containing `base + 0x133bc8` to RW,
3. replace the six wifi pointers with its own handlers,

all **before** the first `startGame` / memory-map init, without modifying the original binary.

## Raising the wifi IRQ (ARM7 IRQ bit 24)

DraStic raises IRQs inline; the ARM7 I/O write handler at `0x25f3c`–`0x25f88` shows the pattern:

```
io  = *(*(ctx) + 0x1000010) -> +0x2080      ; ARM7 I/O register block
io[0x214] |= irq_bit                         ; IF
cpu = *(*(ctx) + 0x1000010)
if ((cpu[0x2110] & 6) == 0)
    cpu[0x2108] = io[0x210] & io[0x214] & -io[0x208]   ; IE & IF & (IME ? ~0 : 0)
```

A hook library can replicate this to deliver W_IF-driven interrupts.

## Timing

The timer read path (`0x22ba8`) shows how to compute the current system cycle count:
`cyc = (*(u32*)(evt + 0x8) + *(u32*)(evt + 0x10)) - *(u32*)(sys + 0x2290)` where
`evt = *(sys + 0x2258)`. This can back W_US_COUNT lazily on register reads.

## Still unknown / remaining work

- **Scheduler hook.** A wifi chip must be able to raise IRQs while the ARM7 is halted (beacons, RX,
  TX-done). This needs a periodic tick from DraStic's event scheduler (e.g. hooking the
  scanline/HBlank event) — not located yet.
- **Wifi chip emulation.** Registers, TX/RX queues, W_US timers, beacons, plus a fake access point
  (melonDS `Wifi.cpp` / `WifiAP.cpp` are the reference; they are GPL-licensed).
- **Network bridge.** A user-mode NAT (DHCP, ARP, DNS, TCP/UDP proxy over Android sockets), like
  melonDS's slirp backend. DNS should point at a revival service (e.g. Wiimmfi `167.235.229.36`).
- **Firmware WFC settings.** Connection slot pointing at the fake AP SSID, filled into DraStic's
  firmware image.
- **APK side.** `INTERNET` permission, `System.loadLibrary` of the hook library right after
  `libdrastic`, and a settings toggle.
- Only arm64 has been analysed (the target device, Anbernic RG DS, is arm64).

## Step 1: wifi access logger (`wfc/`)

`wfc/src/wfc_hook.c` builds `libdrastic_wfc.so` (arm64 only; `ANDROID_NDK_HOME=… ./wfc/build.sh`
writes it to `universal/lib/arm64-v8a/`). `DraSticJNI.<clinit>` loads it right after
`libdrastic_arm64` (only on arm64 and only when the core loaded; any failure is swallowed).

On load it checks that the handler table holds exactly the expected r2.6.0.4a pointers, then swaps in
wrappers that call the original handlers and log accesses. Emulation behaviour is unchanged.

Output (tag `DraSticWFC`):

- `adb logcat -s DraSticWFC`, and/or
- `Android/data/<package>/files/wfc_log.txt` (if the directory exists and is writable).

What it logs: `wifi handlers hooked` at startup, `first wifi access - hook is live` once a game
touches the wifi region, the first 16 reads/writes per register (`R16 04800000 -> 00000000`), and
every ~2 s a summary of registers that were accessed more often than that.

To test: open a WFC game, go into its Nintendo WFC / online menu and try to connect, then grab
the log. If `wifi handlers hooked` appears but `hook is live` never does, the game never touched
the wifi hardware (or the hook was installed too late).
