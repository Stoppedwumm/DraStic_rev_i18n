/*
 * libdrastic_wfc.so - wifi register access logger for DraStic r2.6.0.4a (arm64).
 *
 * Step 1 of WFC support (see docs/wfc-research.md): replace the six ARM7 wifi
 * region handlers in libdrastic_arm64.so's static handler table with wrappers
 * that call the originals and log every access. No emulation behaviour changes.
 *
 * Output goes to logcat (tag "DraSticWFC") and, when writable, to
 * <external storage>/Android/data/<package>/files/wfc_log.txt.
 *
 * Off by default. Enable before starting the app with:
 *   adb shell setprop debug.drastic.wfc 1   (summaries + register accesses)
 *   adb shell setprop debug.drastic.wfc 2   (also individual wifi RAM accesses)
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
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <time.h>
#include <unistd.h>

#define TAG "DraSticWFC"

#define CORE_LIB "libdrastic_arm64.so"

/* Offsets in libdrastic_arm64.so r2.6.0.4a (BuildID 2318f180e6c9aca2...). */
#define TABLE_WIFI_READ  0x133bc8
#define TABLE_WIFI_WRITE 0x133be0

static const uintptr_t expected_read[3] = { 0x261b8, 0x261c0, 0x26274 };
static const uintptr_t expected_write[3] = { 0x24ebc, 0x24ec0, 0x24f38 };

typedef uint32_t (*read_fn)(void *state, uint32_t addr);
typedef void (*write_fn)(void *state, uint32_t addr, uint32_t value);

static read_fn orig_read[3];
static write_fn orig_write[3];

static FILE *log_file;

/* Per-register access statistics, indexed by (addr & 0xFFFF) >> 1. */
#define REG_SLOTS 0x8000
#define DETAIL_LIMIT 4
/* Hard cap on per-access lines so logging can never stall emulation for long. */
#define DETAIL_TOTAL_LIMIT 2000

static int log_level;
static uint32_t detail_lines;

typedef struct {
    uint32_t reads;
    uint32_t writes;
} reg_stats;

static reg_stats stats[REG_SLOTS];
static uint64_t last_summary_ns;
static uint64_t total_accesses;

static void log_line(const char *fmt, ...)
{
    char buf[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    __android_log_write(ANDROID_LOG_INFO, TAG, buf);
    if (log_file) {
        fputs(buf, log_file);
        fputc('\n', log_file);
    }
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

    log_line("--- summary (%llu accesses total) ---", (unsigned long long)total_accesses);
    for (i = 0; i < REG_SLOTS; i++) {
        if (stats[i].reads > DETAIL_LIMIT || stats[i].writes > DETAIL_LIMIT)
            log_line("  reg %04X: %u reads, %u writes", i << 1, stats[i].reads, stats[i].writes);
        stats[i].reads = 0;
        stats[i].writes = 0;
    }
    if (log_file)
        fflush(log_file);
}

static void record(int is_write, int size, uint32_t addr, uint32_t value)
{
    reg_stats *s = &stats[(addr & 0xFFFF) >> 1];
    uint32_t n = is_write ? ++s->writes : ++s->reads;

    total_accesses++;
    if (total_accesses == 1)
        log_line("first wifi access - hook is live");
    /* 0x4000-0x5FFF is wifi RAM; the game self-tests all of it on boot. */
    if ((addr & 0xC000) == 0x4000 && log_level < 2)
        n = DETAIL_LIMIT + 1;
    if (n <= DETAIL_LIMIT && detail_lines < DETAIL_TOTAL_LIMIT && ++detail_lines)
        log_line("%c%d %08X %s %08X", is_write ? 'W' : 'R', size, addr, is_write ? "<-" : "->", value);
    maybe_summarize();
}

static uint32_t hook_read8(void *state, uint32_t addr)
{
    uint32_t v = orig_read[0](state, addr);
    record(0, 8, addr, v);
    return v;
}

static uint32_t hook_read16(void *state, uint32_t addr)
{
    uint32_t v = orig_read[1](state, addr);
    record(0, 16, addr, v);
    return v;
}

static uint32_t hook_read32(void *state, uint32_t addr)
{
    uint32_t v = orig_read[2](state, addr);
    record(0, 32, addr, v);
    return v;
}

static void hook_write8(void *state, uint32_t addr, uint32_t value)
{
    record(1, 8, addr, value);
    orig_write[0](state, addr, value);
}

static void hook_write16(void *state, uint32_t addr, uint32_t value)
{
    record(1, 16, addr, value);
    orig_write[1](state, addr, value);
}

static void hook_write32(void *state, uint32_t addr, uint32_t value)
{
    record(1, 32, addr, value);
    orig_write[2](state, addr, value);
}

static void open_log_file(void)
{
    char pkg[128] = { 0 };
    char path[512];
    const char *ext = getenv("EXTERNAL_STORAGE");
    FILE *f = fopen("/proc/self/cmdline", "r");

    if (f) {
        size_t n = fread(pkg, 1, sizeof(pkg) - 1, f);
        pkg[n] = '\0';
        fclose(f);
    }
    if (!pkg[0])
        return;
    if (!ext)
        ext = "/sdcard";

    /* The app-specific external dir may not exist yet; it is ours to create. */
    snprintf(path, sizeof(path), "%s/Android/data/%s", ext, pkg);
    mkdir(path, 0770);
    snprintf(path, sizeof(path), "%s/Android/data/%s/files", ext, pkg);
    mkdir(path, 0770);

    snprintf(path, sizeof(path), "%s/Android/data/%s/files/wfc_log.txt", ext, pkg);
    log_file = fopen(path, "w");
    if (log_file)
        __android_log_print(ANDROID_LOG_INFO, TAG, "logging to %s", path);
    else
        __android_log_print(ANDROID_LOG_INFO, TAG, "cannot open %s: %s", path, strerror(errno));
}

static int install_hooks(void)
{
    void *handle = dlopen(CORE_LIB, RTLD_NOW | RTLD_NOLOAD);
    void *sym;
    Dl_info info;
    uintptr_t base, start, end;
    uintptr_t *rtab, *wtab;
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
    wtab = (uintptr_t *)(base + TABLE_WIFI_WRITE);

    /* Refuse to touch anything unless this is exactly the build we analysed. */
    for (i = 0; i < 3; i++) {
        if (rtab[i] != base + expected_read[i] || wtab[i] != base + expected_write[i]) {
            log_line("handler table mismatch (unsupported DraStic build), not hooking");
            return -1;
        }
    }

    for (i = 0; i < 3; i++) {
        orig_read[i] = (read_fn)rtab[i];
        orig_write[i] = (write_fn)wtab[i];
    }

    /* The table lives in RELRO, so temporarily make it writable. */
    start = (uintptr_t)rtab & ~(uintptr_t)(page - 1);
    end = ((uintptr_t)(wtab + 3) + page - 1) & ~(uintptr_t)(page - 1);
    if (mprotect((void *)start, end - start, PROT_READ | PROT_WRITE) != 0) {
        log_line("mprotect RW failed: %s", strerror(errno));
        return -1;
    }

    rtab[0] = (uintptr_t)hook_read8;
    rtab[1] = (uintptr_t)hook_read16;
    rtab[2] = (uintptr_t)hook_read32;
    wtab[0] = (uintptr_t)hook_write8;
    wtab[1] = (uintptr_t)hook_write16;
    wtab[2] = (uintptr_t)hook_write32;

    mprotect((void *)start, end - start, PROT_READ);
    log_line("wifi handlers hooked (core base %p)", (void *)base);
    return 0;
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    char prop[PROP_VALUE_MAX] = { 0 };

    (void)vm;
    (void)reserved;

    __system_property_get("debug.drastic.wfc", prop);
    log_level = atoi(prop);
    if (log_level <= 0) {
        __android_log_write(ANDROID_LOG_INFO, TAG, "disabled (setprop debug.drastic.wfc 1 to enable)");
        return JNI_VERSION_1_6;
    }

    open_log_file();
    last_summary_ns = now_ns();
    install_hooks();
    return JNI_VERSION_1_6;
}
