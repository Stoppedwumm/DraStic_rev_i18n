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
0x133b98  ARM7 I/O   read8/16/32   (0x23250, 0x2301c, 0x23280)
0x133bb0  ARM7 I/O   write8/16/32  (0x24f3c, 0x25588, 0x25da0)  (also handles wifi writes)
0x133bc8  ARM7 wifi  read8/16/32   (0x261b8, 0x261c0, 0x26274)
0x133be0  ARM7 wifi  write8/16/32  (0x24ebc, 0x24ec0, 0x24f38)  (not used for writes)
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

The hook is **off by default** (the library loads but does nothing). Enable it before starting the app:

```
adb shell setprop debug.drastic.wfc 1   # register accesses + summaries
adb shell setprop debug.drastic.wfc 2   # also individual wifi RAM accesses
adb shell setprop debug.drastic.wfc 0   # off again
```

The property resets on reboot.

Output (tag `DraSticWFC`):

- `adb logcat -s DraSticWFC`, and/or
- `Android/data/<package>/files/wfc_log.txt` (the directory is created if missing).

What it logs: `wifi handlers hooked` at startup, `first wifi access - hook is live` once a game
touches the wifi region, the first 4 reads/writes per register (`R16 04808000 -> 00000000`, capped at
2000 lines in total so logging cannot stall emulation), and every ~2 s a summary of registers that
were accessed more often than that.

To test: open a WFC game, go into its Nintendo WFC / online menu and try to connect, then grab
the log. If `wifi handlers hooked` appears but `hook is live` never does, the game never touched
the wifi hardware (or the hook was installed too late).

### First results (RG DS)

- The hook is live; games run the normal wifi init: a full wifi RAM self-test (`0x4000`–`0x5FFF`),
  register mask tests, BB/RF busy polling (`0x15E`, `0x180`), baseband reads (`0x158`/`0x15C`),
  `W_RANDOM` (`0x044`, always 0 in the stub).
- Registers are accessed through the `+0x8000` mirror (`0x04808000`…).
- **No writes were logged**, yet written values read back correctly. Cause: the triplet at
  `0x133bb0` is the ARM7 I/O **write** table (the map init stores `0x133b98`/`0x133bb0` and
  `0x133bc8`/`0x133be0` as read/write pairs), and ARM7 I/O write16 (`0x25588`) handles offsets
  `>= 0x800000` inline at `0x256d8` with the same code as the wifi write16 stub. So wifi writes
  arrive via the I/O write handlers, and the `0x133be0` wifi write slots are effectively dead.
  Hooking the I/O write table is not enough either: the recompiled ARM7 code's memory write
  stub (`0x8316c`–`0x831a4`) calls `0x25588` **directly** for any `0x04xxxxxx` address. write32
  (`0x25da0`) drops wifi writes (`lsr w8, w21, #23; cbnz`), and write8 does not handle them, so
  write16 is the only wifi write path. The logger (v4) therefore inline-patches the entry of `0x25588`
  (`ldr x16, #8; br x16; .quad hook`; the four original `stp`s are moved into a trampoline). The text
  page is switched straight to RWX and back to RX, never dropping exec. A wifi chip emulation must
  intercept writes the same way.
- Seen while a game tries to connect (error 50099): it polls `0x19C` (W_RF_PINS) ~100k times/s
  and reads `0x0D0` (W_RXFILTER) as `0x581`, which it must have written, so writes do happen.
- The first build logged every RAM access synchronously (~30k lines), which coincided with graphics
  glitches. Logging is now throttled and gated behind the property above.

### What a game does when it tries to connect (v4 log, error 50099)

Register names per GBATEK (offsets relative to `0x04808000`, i.e. the `+0x8000` mirror).

1. **Self-test:** writes `0xFFFF`, `0x5A5A`, `0xA5A5` and a counting pattern to the MAC, BSSID and RX/TX
   buffer registers and reads them back (mask check), then fills/checks wifi RAM.
2. **Baseband/RF init:** `W_BB_CNT` (`0x158`) reads/writes polling `W_BB_BUSY` (`0x15E`); RF writes via
   `W_RF_DATA2/1` (`0x17C`/`0x17E`) polling `W_RF_BUSY` (`0x180`); `W_RF_CNT` (`0x184`) = `0x18`.
3. **MAC setup:** MAC `00:01:02:03:04:05` written to `0x018`–`0x01C` (from firmware); `W_IE` (`0x012`) =
   `0xE03F`; `W_US_COUNTCNT`/`W_US_COMPARECNT` (`0x0E8`/`0x0EA`) = 1; `W_RXCNT` (`0x030`) = `0x8000`;
   RX buffer `0x4BFC`–`0x5F60`; `W_RXFILTER` (`0x0D0`) = `0x581`; `W_RXFILTER2` (`0x0E0`) = `0xB`;
   `W_TXREQ_SET` (`0x0AE`) = `0xD`.
4. **Wake-up:** `W_POWERFORCE` (`0x040`) = `0x8001` then `0`, `W_POWERSTATE` (`0x03C`) = `2`, then it
   reads `W_POWERSTATE`, which the stub always returns as `0x0200` (still asleep), and `W_RF_STATUS`
   (`0x214`), which stays `0`.
5. **Scan loop:** polls `W_RF_PINS` (`0x19C`, always 0 in the stub) ~110k times/s for ~2 s per
   attempt, re-runs steps 3–4 (55 times in this log), then fails with **error 50099**.

So the chip never powers up or enters RX, no `W_US_COMPARE`/RX interrupts arrive, and no beacon is
ever received. The emulation has to provide, at minimum: the power state machine (`0x03C`/`0x040`),
`W_RF_STATUS`/`W_RF_PINS`, `W_US_COUNT`/`W_US_COMPARE` with IRQs, and RX of beacons from a fake AP into
the RX ring buffer in wifi RAM. Timers and IRQs while the ARM7 is halted need the scheduler hook.

## Step 2: wifi chip + fake access point (`wfc/`, v5)

`libdrastic_wfc.so` now replaces DraStic's wifi stub entirely when `debug.drastic.wfc` is set:

| Piece | How |
|---|---|
| Wifi reads | wifi read table (`0x133bc8`) → `wifi_read16()` |
| Wifi writes | inline patch of ARM7 I/O write16 (`0x25588`) and write32 (`0x25da0`); offsets `>= 0x800000` go to `wifi_write16()`, the rest to the original handler |
| Time | inline patch of the scanline event handler (`0x2c8f8`, VCOUNT at `sys+0x14`); every call advances the chip by one line (2130 cycles at 33.513982 MHz ≈ 63.6 µs), processed in 8 µs steps |
| Wifi IRQ | `root = *(state+0xFBA88)`, `cpu = *(root+0x1000010)`, `io = *(cpu+0x2080)`: `io[0x214] \|= 1<<24`, and if `!(cpu[0x2110] & 6)`, `cpu[0x2108] = IE & IF & -IME` (same as the VBlank code at `0x2ca60`) |

The chip (`wifi.c`) and AP (`wifi_ap.c`) are a C port of melonDS's `Wifi.cpp` / `WifiAP.cpp`
without local multiplayer, so `wfc/` is GPLv3 (`wfc/LICENSE`). Implemented: power state machine
(W_POWERSTATE/W_POWERFORCE/W_POWERDOWNCTRL, IRQ11), W_US_COUNT/W_US_COMPARE/beacon counters
(IRQ13/14/15), TX via LOC1–3 (IRQ7/IRQ1, TX status, sequence numbers), RX into the ring buffer with
the hardware header and address/BSSID filtering (IRQ6/IRQ0), RX/TX buffer data ports, BB registers,
RF register storage.

The AP is called `DraSticWFC` (MAC `02:00:44:57:46:43`, channel 6). It sends beacons every 128 ms,
answers probe requests, authentication and association. **It answers on every channel**, because
DraStic's built-in firmware has no RF channel tables (the RF writes in the log are all zero), so the
selected channel cannot be decoded.

Not done yet: the network bridge. Data frames from the console (DHCP, DNS, …) are dropped and
counted, so a connection test will still fail after association.

Checked on the host by replaying the v4 register log against `wifi.c`: the transceiver powers up
(`W_RF_STATUS` = 1, `W_RF_PINS` = `0x84`), beacons land in the RX ring with header flags `0x0011`,
and IRQ0/IRQ6 fire.

Enable with `adb shell setprop debug.drastic.wfc 1` (`2` adds register accesses, `3` wifi RAM).
With `0` / unset, DraStic's stock stub is used.
