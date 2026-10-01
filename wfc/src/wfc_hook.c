/*
 * libdrastic_wfc.so - Nintendo Wi-Fi Connection support for DraStic r2.6.0.4a
 * (arm64). See docs/wfc-research.md.
 *
 * Copyright (C) 2026 DraStic_rev_i18n contributors
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version. See wfc/LICENSE.
 *
 * Replaces DraStic's ARM7 wifi stub with an emulated wifi chip (wifi.c) and a
 * fake access point (wifi_ap.c):
 *  - wifi reads: the wifi read handlers in the static handler table,
 *  - wifi writes: inline patch of the ARM7 I/O write16/write32 handlers (the
 *    recompiled code calls them directly),
 *  - time: inline patch of the scanline event handler.
 *
 * Off by default. Enable before starting the app with:
 *   adb shell setprop debug.drastic.wfc 1   (emulation + event log)
 *   adb shell setprop debug.drastic.wfc 2   (+ register accesses)
 *   adb shell setprop debug.drastic.wfc 3   (+ wifi RAM accesses)
 * Output goes to logcat (tag "DraSticWFC").
 */

#include <android/log.h>
#include <dlfcn.h>
#include <errno.h>
#include <jni.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <time.h>
#include <unistd.h>

#include "wfc.h"

#define TAG "DraSticWFC"

#define CORE_LIB "libdrastic_arm64.so"

/* Bump on every change so logs show which build produced them. */
#define WFC_VERSION 6

/* Offsets in libdrastic_arm64.so r2.6.0.4a (BuildID 2318f180e6c9aca2...). */
#define TABLE_WIFI_READ  0x133bc8
#define IO_WRITE16       0x25588
#define IO_WRITE32       0x25da0
#define SCANLINE_EVENT   0x2c8f8

/*
 * Reads of 0x048xxxxx go through the wifi read table. Writes do not: the
 * recompiled ARM7 code calls the ARM7 I/O write handlers directly (bl at
 * 0x831a4), which handle offsets >= 0x800000 inline (write16 at 0x256d8;
 * write32 drops them).
 */
static const uintptr_t expected_read[3] = { 0x261b8, 0x261c0, 0x26274 };

/* Prologue of IO_WRITE16 and IO_WRITE32: stp x24,x23,[sp,#-0x40]!;
 * stp x22,x21,[sp,#0x10]; stp x20,x19,[sp,#0x20]; stp x29,x30,[sp,#0x30]. */
static const uint32_t io_write_prologue[4] = { 0xa9bc5ff8, 0xa90157f6, 0xa9024ff4, 0xa9037bfd };
/* Prologue of SCANLINE_EVENT: str x27,[sp,#-0x60]!; stp x26,x25,[sp,#0x10];
 * stp x24,x23,[sp,#0x20]; stp x22,x21,[sp,#0x30]. */
static const uint32_t scanline_prologue[4] = { 0xf81a0ffb, 0xa90167fa, 0xa9025ff8, 0xa90357f6 };

/*
 * ARM7 state layout, from the ARM7 write8 handler's own IE/IF/IME path
 * (0x253c4): the ARM7 I/O registers are inline in the handler state, and the
 * CPU is reached through state+0xFBA90. (state+0xFBA88 leads to the ARM9; the
 * write32 code at 0x25f3c uses it to raise the IPC FIFO IRQ there.)
 */
#define STATE_IO7      0x23070     /* ARM7 I/O registers, indexed by offset */
#define STATE_SELF     0xFBA90     /* -> system whose +ROOT_CPU is the ARM7 */
#define ROOT_CPU       0x1000010
#define CPU_IRQ_PEND   0x2108
#define CPU_EXIT_FLAGS 0x22a8      /* bit1: re-check IRQs */
#define IO_IME         0x208
#define IO_IE          0x210
#define IO_IF          0x214
#define IRQ_WIFI       (1u << 24)

/* One scanline is 2130 cycles at 33.513982 MHz. */
#define LINE_CYCLES 2130ull
#define ARM7_HZ 33513982ull

#define IS_WIFI(addr) (((addr) & 0xFFFFFF) >= 0x800000)

typedef uint32_t (*read_fn)(void *state, uint32_t addr);
typedef void (*write_fn)(void *state, uint32_t addr, uint32_t value);
/* The scanline handler's exact arguments are unknown; forward all of them. */
typedef void (*event_fn)(uint64_t, uint64_t, uint64_t, uint64_t,
                         uint64_t, uint64_t, uint64_t, uint64_t);

static read_fn orig_read[3];
static write_fn orig_write16;
static write_fn orig_write32;
static event_fn orig_scanline;

int log_level;
static uint8_t *wifi_state;
static uint64_t line_us_frac;

/* Per-register access statistics, indexed by (addr & 0xFFFF) >> 1. */
#define REG_SLOTS 0x8000
#define DETAIL_LIMIT 4
/* Hard cap on per-access lines so logging can never stall emulation for long. */
#define DETAIL_TOTAL_LIMIT 2000

typedef struct {
    uint32_t reads;
    uint32_t writes;
} reg_stats;

static uint32_t detail_lines;
static reg_stats stats[REG_SLOTS];
static uint64_t last_summary_ns;
static uint64_t total_accesses;
static uint32_t scanlines;
static uint32_t wifi_irqs;

void log_line(const char *fmt, ...)
{
    char buf[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    __android_log_write(ANDROID_LOG_INFO, TAG, buf);
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* Every ~2s: dump the registers touched since the last summary, then reset. */
static void maybe_summarize(void)
{
    uint64_t now = now_ns();
    uint32_t i;

    if (now - last_summary_ns < 2000000000ull)
        return;
    last_summary_ns = now;

    log_line("--- summary (%llu accesses, %u scanlines, %u wifi IRQs) ---",
             (unsigned long long)total_accesses, scanlines, wifi_irqs);
    scanlines = 0;
    wifi_irqs = 0;
    if (log_level < 2)
        return;
    for (i = 0; i < REG_SLOTS; i++) {
        if (stats[i].reads > DETAIL_LIMIT || stats[i].writes > DETAIL_LIMIT)
            log_line("  reg %04X: %u reads, %u writes", i << 1, stats[i].reads, stats[i].writes);
        stats[i].reads = 0;
        stats[i].writes = 0;
    }
}

static void record(int is_write, int size, uint32_t off, uint32_t value)
{
    reg_stats *s = &stats[(off & 0xFFFF) >> 1];
    uint32_t n = is_write ? ++s->writes : ++s->reads;

    total_accesses++;
    if (log_level < 2)
        return;
    /* 0x4000-0x5FFF is wifi RAM; the game self-tests all of it on boot. */
    if ((off & 0xC000) == 0x4000 && log_level < 3)
        return;
    if (n <= DETAIL_LIMIT && detail_lines < DETAIL_TOTAL_LIMIT && ++detail_lines)
        log_line("%c%d %04X %s %04X", is_write ? 'W' : 'R', size, off & 0xFFFF,
                 is_write ? "<-" : "->", value);
}

/* ---- ARM7 interrupt ---- */

void arm7_wifi_irq(void)
{
    uint8_t *cpu, *io;
    uint32_t *iflags, pending;

    if (!wifi_state)
        return;
    io = wifi_state + STATE_IO7;
    cpu = *(uint8_t **)(*(uint8_t **)(wifi_state + STATE_SELF) + ROOT_CPU);

    iflags = (uint32_t *)(io + IO_IF);
    *iflags |= IRQ_WIFI;
    pending = *(uint32_t *)(io + IO_IE) & *iflags & -*(uint32_t *)(io + IO_IME);
    *(uint32_t *)(cpu + CPU_IRQ_PEND) = pending;
    if (pending)
        *(uint32_t *)(cpu + CPU_EXIT_FLAGS) |= 2;
    wifi_irqs++;
}

/* ---- hooks ---- */

static void attach(void *state)
{
    if (wifi_state == state)
        return;
    if (wifi_state) {
        log_line("wifi state pointer changed %p -> %p", (void *)wifi_state, state);
    } else {
        log_line("first wifi access - emulation is live");
        wifi_reset();
    }
    wifi_state = state;
}

/* Read handlers get the offset inside 0x04800000. */
static uint32_t hook_read8(void *state, uint32_t addr)
{
    uint32_t off = addr & 0xFFFFF;
    uint32_t v;

    attach(state);
    v = (wifi_read16(off & ~1u) >> ((off & 1) * 8)) & 0xFF;
    record(0, 8, off, v);
    return v;
}

static uint32_t hook_read16(void *state, uint32_t addr)
{
    uint32_t off = addr & 0xFFFFF;
    uint32_t v;

    attach(state);
    v = wifi_read16(off);
    record(0, 16, off, v);
    maybe_summarize();
    return v;
}

static uint32_t hook_read32(void *state, uint32_t addr)
{
    uint32_t off = addr & 0xFFFFF;
    uint32_t v;

    attach(state);
    v = wifi_read16(off) | ((uint32_t)wifi_read16(off + 2) << 16);
    record(0, 32, off, v);
    return v;
}

/* I/O write handlers get the offset inside 0x04000000. */
static void hook_write16(void *state, uint32_t addr, uint32_t value)
{
    uint32_t off;

    if (!IS_WIFI(addr)) {
        orig_write16(state, addr, value);
        return;
    }
    off = (addr & 0xFFFFFF) - 0x800000;
    attach(state);
    record(1, 16, off, value & 0xFFFF);
    wifi_write16(off, value);
}

static void hook_write32(void *state, uint32_t addr, uint32_t value)
{
    uint32_t off;

    if (!IS_WIFI(addr)) {
        orig_write32(state, addr, value);
        return;
    }
    off = (addr & 0xFFFFFF) - 0x800000;
    attach(state);
    record(1, 32, off, value);
    wifi_write16(off, value & 0xFFFF);
    wifi_write16(off + 2, value >> 16);
}

static void hook_scanline(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                          uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7)
{
    if (wifi_state) {
        uint32_t us;

        line_us_frac += LINE_CYCLES * 1000000ull;
        us = line_us_frac / ARM7_HZ;
        line_us_frac %= ARM7_HZ;
        wifi_advance(us);
        scanlines++;
    }
    orig_scanline(a0, a1, a2, a3, a4, a5, a6, a7);
}

/* ---- installation ---- */

/* ldr x16, #8; br x16; .quad target */
static void put_abs_jump(uint32_t *at, uintptr_t target)
{
    at[0] = 0x58000050;
    at[1] = 0xd61f0200;
    memcpy(&at[2], &target, sizeof(target));
}

/*
 * Redirect the function at fn to hook. Returns a callable copy of the original
 * (relocated prologue + jump back), or NULL on failure with fn left untouched.
 * The prologue must be four position-independent instructions.
 */
static void *inline_hook(uintptr_t fn, void *hook, const uint32_t prologue[4], const char *name)
{
    long page = sysconf(_SC_PAGESIZE);
    uintptr_t start = fn & ~(uintptr_t)(page - 1);
    uintptr_t end = (fn + 16 + page - 1) & ~(uintptr_t)(page - 1);
    uint32_t *tramp;

    if (memcmp((void *)fn, prologue, 16) != 0) {
        log_line("%s prologue mismatch, not hooking", name);
        return NULL;
    }

    tramp = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (tramp == MAP_FAILED) {
        log_line("trampoline mmap failed: %s", strerror(errno));
        return NULL;
    }
    memcpy(tramp, prologue, 16);
    put_abs_jump(tramp + 4, fn + 16);
    if (mprotect(tramp, page, PROT_READ | PROT_EXEC) != 0) {
        log_line("trampoline mprotect failed: %s", strerror(errno));
        munmap(tramp, page);
        return NULL;
    }
    __builtin___clear_cache((char *)tramp, (char *)(tramp + 8));

    /* Keep PROT_EXEC throughout: the page is live code. */
    if (mprotect((void *)start, end - start, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        log_line("text mprotect RWX failed: %s", strerror(errno));
        munmap(tramp, page);
        return NULL;
    }
    put_abs_jump((uint32_t *)fn, (uintptr_t)hook);
    mprotect((void *)start, end - start, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char *)fn, (char *)fn + 16);
    return tramp;
}

static int install_hooks(void)
{
    void *handle = dlopen(CORE_LIB, RTLD_NOW | RTLD_NOLOAD);
    void *sym;
    Dl_info info;
    uintptr_t base, start, end;
    uintptr_t *rtab;
    long page = sysconf(_SC_PAGESIZE);
    int i;

    if (!handle) {
        log_line("core library not loaded: %s", dlerror());
        return -1;
    }
    sym = dlsym(handle, "JNI_OnLoad");
    if (!sym || !dladdr(sym, &info) || !info.dli_fbase) {
        log_line("cannot locate core library base");
        return -1;
    }
    base = (uintptr_t)info.dli_fbase;
    rtab = (uintptr_t *)(base + TABLE_WIFI_READ);

    /* Refuse to touch anything unless this is exactly the build we analysed. */
    for (i = 0; i < 3; i++) {
        if (rtab[i] != base + expected_read[i]) {
            log_line("handler table mismatch (unsupported DraStic build), not hooking");
            return -1;
        }
    }
    if (memcmp((void *)(base + IO_WRITE16), io_write_prologue, 16) != 0 ||
        memcmp((void *)(base + IO_WRITE32), io_write_prologue, 16) != 0 ||
        memcmp((void *)(base + SCANLINE_EVENT), scanline_prologue, 16) != 0) {
        log_line("code mismatch (unsupported DraStic build), not hooking");
        return -1;
    }

    /* Writes and time first: without them, emulated reads would be useless. */
    orig_write16 = (write_fn)inline_hook(base + IO_WRITE16, (void *)hook_write16,
                                         io_write_prologue, "write16");
    if (!orig_write16)
        return -1;
    orig_write32 = (write_fn)inline_hook(base + IO_WRITE32, (void *)hook_write32,
                                         io_write_prologue, "write32");
    orig_scanline = (event_fn)inline_hook(base + SCANLINE_EVENT, (void *)hook_scanline,
                                          scanline_prologue, "scanline");
    if (!orig_write32 || !orig_scanline) {
        /* write16 is already redirected; it is harmless without the rest. */
        log_line("partial install, wifi emulation will not work");
        return -1;
    }

    for (i = 0; i < 3; i++)
        orig_read[i] = (read_fn)rtab[i];

    /* The table lives in RELRO, so temporarily make it writable. */
    start = (uintptr_t)rtab & ~(uintptr_t)(page - 1);
    end = ((uintptr_t)(rtab + 3) + page - 1) & ~(uintptr_t)(page - 1);
    if (mprotect((void *)start, end - start, PROT_READ | PROT_WRITE) != 0) {
        log_line("mprotect RW failed: %s", strerror(errno));
        return -1;
    }
    rtab[0] = (uintptr_t)hook_read8;
    rtab[1] = (uintptr_t)hook_read16;
    rtab[2] = (uintptr_t)hook_read32;
    mprotect((void *)start, end - start, PROT_READ);

    log_line("wifi emulation installed (core base %p)", (void *)base);
    return 0;
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    char prop[PROP_VALUE_MAX] = { 0 };

    (void)vm;
    (void)reserved;

    __system_property_get("debug.drastic.wfc", prop);
    log_level = atoi(prop);
    __android_log_print(ANDROID_LOG_INFO, TAG, "libdrastic_wfc v%d, debug.drastic.wfc=%d",
                        WFC_VERSION, log_level);
    if (log_level <= 0) {
        __android_log_write(ANDROID_LOG_INFO, TAG, "disabled (setprop debug.drastic.wfc 1 to enable)");
        return JNI_VERSION_1_6;
    }

    last_summary_ns = now_ns();
    install_hooks();
    return JNI_VERSION_1_6;
}
