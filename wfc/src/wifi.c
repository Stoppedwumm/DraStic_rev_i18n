/*
 * Nintendo DS wifi chip emulation (infrastructure mode only, no local
 * multiplayer). C port of melonDS's Wifi.cpp (Copyright 2016-2025 melonDS
 * team, GPLv3), with register documentation from GBATEK.
 *
 * Copyright (C) 2026 DraStic_rev_i18n contributors
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version. See wfc/LICENSE.
 */

#include <string.h>

#include "wfc.h"

/* Register offsets (GBATEK names in comments). */
enum {
    W_ID = 0x000,
    W_MODE_RST = 0x004,
    W_MODE_WEP = 0x006,
    W_TXSTATCNT = 0x008,
    W_IF = 0x010,
    W_IE = 0x012,
    W_MACADDR0 = 0x018,
    W_BSSID0 = 0x020,
    W_AID_LOW = 0x028,
    W_AID_FULL = 0x02A,
    W_RXCNT = 0x030,
    W_WEP_CNT = 0x032,
    W_TRX_POWER = 0x034,     /* W_INTERNAL */
    W_POWER_US = 0x036,
    W_POWER_TX = 0x038,
    W_POWERSTATE = 0x03C,
    W_POWERFORCE = 0x040,
    W_RANDOM = 0x044,
    W_POWERDOWNCTRL = 0x048,
    W_RXBUF_BEGIN = 0x050,
    W_RXBUF_END = 0x052,
    W_RXBUF_WRCSR = 0x054,
    W_RXBUF_WR_ADDR = 0x056,
    W_RXBUF_RD_ADDR = 0x058,
    W_RXBUF_READCSR = 0x05A,
    W_RXBUF_COUNT = 0x05C,
    W_RXBUF_RD_DATA = 0x060,
    W_RXBUF_GAP = 0x062,
    W_RXBUF_GAPDISP = 0x064,
    W_TXBUF_WR_ADDR = 0x068,
    W_TXBUF_COUNT = 0x06C,
    W_TXBUF_WR_DATA = 0x070,
    W_TXBUF_GAP = 0x074,
    W_TXBUF_GAPDISP = 0x076,
    W_TXBUF_BEACON = 0x080,
    W_LISTENCOUNT = 0x088,
    W_BEACONINT = 0x08C,
    W_LISTENINT = 0x08E,
    W_TXBUF_CMD = 0x090,
    W_TXBUF_REPLY1 = 0x094,
    W_TXBUF_REPLY2 = 0x098,
    W_TXBUF_LOC1 = 0x0A0,
    W_TXREQ_RESET = 0x0AC,
    W_TXREQ_SET = 0x0AE,
    W_TXREQ_READ = 0x0B0,
    W_TXBUF_RESET = 0x0B4,
    W_TXBUSY = 0x0B6,
    W_TXSTAT = 0x0B8,
    W_PREAMBLE = 0x0BC,
    W_CMD_TOTALTIME = 0x0C0,
    W_CMD_REPLYTIME = 0x0C4,
    W_RXFILTER = 0x0D0,
    W_RXLEN_CROP = 0x0DA,
    W_RXFILTER2 = 0x0E0,
    W_US_COUNTCNT = 0x0E8,
    W_US_COMPARECNT = 0x0EA,
    W_CMD_COUNTCNT = 0x0EE,
    W_US_COMPARE0 = 0x0F0,
    W_US_COUNT0 = 0x0F8,
    W_CONTENTFREE = 0x10C,
    W_PRE_BEACON = 0x110,
    W_CMD_COUNT = 0x118,
    W_BEACON_COUNT = 0x11C,
    W_POST_BEACON = 0x134,
    W_BB_CNT = 0x158,
    W_BB_WRITE = 0x15A,
    W_BB_READ = 0x15C,
    W_BB_BUSY = 0x15E,
    W_RF_DATA2 = 0x17C,
    W_RF_DATA1 = 0x17E,
    W_RF_BUSY = 0x180,
    W_RF_CNT = 0x184,
    W_TX_HDR_CNT = 0x194,
    W_RF_PINS = 0x19C,
    W_CMD_STAT0 = 0x1D0,
    W_TX_SEQNO = 0x210,
    W_RF_STATUS = 0x214,
    W_IF_SET = 0x21C,
    W_RXTX_ADDR = 0x268,
};

/* The chip is advanced in fixed steps, like melonDS's kTimerInterval. */
#define STEP_US 8
#define STEP_MASK (~(uint32_t)(STEP_US - 1))

#define REG(o) io[((o) & 0xFFF) >> 1]
#define RAM16(a) (*(uint16_t *)&ram[(a) & 0x1FFE])

typedef struct {
    int valid;
    uint16_t addr;
    uint16_t length;
    int rate;      /* 1 or 2 Mbit/s */
    int phase;     /* 0 = preamble, 1 = data */
    int32_t phase_time;
} tx_slot;

static uint16_t io[0x800];
static uint8_t ram[0x2000];
static uint8_t bb_regs[0x100];
static uint8_t bb_ro[0x100];
static uint32_t rf_regs[0x40];

static uint16_t random_val;
static uint64_t us_timestamp;
static uint64_t us_counter;
static uint64_t us_compare;
static int block_beacon_irq14;
static int32_t us_until_power_on;
static uint32_t cmd_counter;

/* Slots: 0=LOC1, 1=CMD (not emulated), 2=LOC2, 3=LOC3, 4=beacon. */
static tx_slot tx_slots[5];
static int tx_cur = -1;
static int com_status;   /* bit0 = receiving, bit1 = transmitting */
static uint32_t rx_counter;
static uint8_t rx_buffer[2048];
static int32_t rx_time;
static uint8_t tx_buffer[2048];
static uint32_t step_remainder;

const uint8_t *wifi_mac(void)
{
    return (const uint8_t *)&REG(W_MACADDR0);
}

static int mac_equal(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, 6) == 0;
}

void wifi_reset(void)
{
    static const uint8_t fixed[] = { 0x00, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x16, 0x17,
                                     0x18, 0x19, 0x1A, 0x27, 0x4D, 0x5D, 0x5E, 0x5F, 0x60,
                                     0x61, 0x64, 0x66 };
    unsigned i;

    memset(io, 0, sizeof(io));
    memset(ram, 0, sizeof(ram));
    memset(bb_regs, 0, sizeof(bb_regs));
    memset(bb_ro, 0, sizeof(bb_ro));
    memset(rf_regs, 0, sizeof(rf_regs));

    for (i = 0; i < sizeof(fixed); i++)
        bb_ro[fixed[i]] = 1;
    for (i = 0x69; i < 0x100; i++)
        bb_ro[i] = 1;
    bb_regs[0x00] = 0x6D;
    bb_regs[0x5D] = 0x01;
    bb_regs[0x64] = 0xFF;

    REG(W_ID) = 0x1440;
    memset(&REG(W_MACADDR0), 0xFF, 6);
    memset(&REG(W_BSSID0), 0xFF, 6);
    REG(W_POWER_US) = 0x0001;

    random_val = 1;
    us_timestamp = 0;
    us_counter = 0;
    us_compare = 0;
    block_beacon_irq14 = 0;
    us_until_power_on = 0;
    cmd_counter = 0;
    memset(tx_slots, 0, sizeof(tx_slots));
    tx_cur = -1;
    com_status = 0;
    rx_counter = 0;
    rx_time = 0;
    step_remainder = 0;

    ap_reset();
}

/* ---- interrupts ---- */

static void check_irq(uint16_t oldflags)
{
    uint16_t newflags = REG(W_IF) & REG(W_IE);

    /* IF.Bit24 is only raised on a 0 -> nonzero transition. */
    if (oldflags == 0 && newflags != 0)
        arm7_wifi_irq();
}

static void set_irq(int irq)
{
    uint16_t oldflags = REG(W_IF) & REG(W_IE);

    REG(W_IF) |= 1 << irq;
    check_irq(oldflags);
}

static void update_power_status(int power);

static void set_irq13(void)
{
    set_irq(13);

    /* Auto power-down only happens in automatic power saving mode (0). */
    if ((REG(W_MODE_WEP) & 7) == 0 && !(REG(W_POWER_TX) & 2))
        update_power_status(-1);
}

static void start_tx_beacon(void);

/* source: 0 = US compare, 1 = beacon count, 2 = forced */
static void set_irq14(int source)
{
    if (source != 2)
        REG(W_BEACON_COUNT) = REG(W_BEACONINT);

    if (block_beacon_irq14 && source == 1)
        return;
    if (!(REG(W_US_COMPARECNT) & 1))
        return;

    set_irq(14);

    REG(W_POST_BEACON) = 0xFFFF;
    REG(W_TXREQ_READ) &= 0xFFF2;

    if (REG(W_TXBUF_BEACON) & 0x8000)
        start_tx_beacon();

    if (REG(W_LISTENCOUNT) == 0)
        REG(W_LISTENCOUNT) = REG(W_LISTENINT);
    REG(W_LISTENCOUNT)--;
}

static void set_irq15(void)
{
    set_irq(15);

    if (REG(W_POWER_TX) & 1)
        update_power_status(1);
}

/* ---- power ---- */

static void set_status(int status)
{
    static const uint16_t rf_pins[10] = { 0x04, 0x84, 0, 0x46, 0, 0x84, 0x87, 0, 0x46, 0x04 };

    REG(W_RF_STATUS) = status;
    REG(W_RF_PINS) = rf_pins[status];
}

/* power: 1 = on, 0 = no change, -1 = off */
static void update_power_status(int power)
{
    int cur = 0, req;

    if (REG(W_TRX_POWER) == 1)
        cur |= 1;
    if (!(REG(W_POWERSTATE) & (1 << 9)))
        cur |= 2;
    req = cur;

    if (REG(W_POWERFORCE) & (1 << 15)) {
        req = (REG(W_POWERFORCE) & 1) ? 0 : 3;
    } else if (!(REG(W_MODE_RST) & 1)) {
        req = 0;
    } else {
        if (power == 0) {
            if ((REG(W_POWERSTATE) & 0x0202) == 0x0202)
                power = 1;
            else if ((REG(W_POWERSTATE) & 0x0201) == 0x0001)
                power = -1;
        }
        /* W_POWERDOWNCTRL bit0 inhibits power-down, bit1 forces wakeup. */
        if (power == -1 && (REG(W_POWERDOWNCTRL) & 1))
            power = 0;

        if (power == 1)
            req = 3;
        else if (power == -1)
            req = REG(W_POWERDOWNCTRL) ? 3 : 0;
        else if (REG(W_POWERDOWNCTRL) & 2)
            req = 3;
    }

    if (req == cur)
        return;

    if (req & 1) {
        if (!(cur & 1)) {
            REG(W_TRX_POWER) = 1;
            set_status(1);
        }
    } else {
        REG(W_TRX_POWER) = 2;
        if (!com_status) {
            REG(W_TRX_POWER) = 0;
            set_status(9);
        }
    }

    if (req & 2) {
        REG(W_POWERSTATE) |= 1 << 8;
        if (!(cur & 2) && us_until_power_on == 0) {
            if (log_level >= 1)
                log_line("wifi: transceiver power on");
            us_until_power_on = -2048;
            set_irq(11);
        }
    } else {
        if ((cur & 2) && log_level >= 1)
            log_line("wifi: transceiver power off");
        REG(W_POWERSTATE) &= ~((1 << 0) | (1 << 8));
        REG(W_POWERSTATE) |= 1 << 9;
        us_until_power_on = 0;
    }
}

/* ---- transmit ---- */

static int preamble_len(int rate)
{
    if (rate == 1)
        return 192;
    return (REG(W_PREAMBLE) & 4) ? 96 : 192;
}

static void tx_send_frame(tx_slot *slot, int num)
{
    int noseqno = 0;
    int len;

    if (ram[slot->addr + 4])
        noseqno = 2;

    if (!noseqno) {
        if (!(REG(W_TX_HDR_CNT) & (1 << 2)))
            RAM16(slot->addr + 0xC + 22) = REG(W_TX_SEQNO) << 4;
        REG(W_TX_SEQNO) = (REG(W_TX_SEQNO) + 1) & 0x0FFF;
    }

    /* WEP frames: no real WEP, but some games require a nonzero WEP FCS. */
    if ((RAM16(slot->addr + 0xC) & (1 << 14)) && (REG(W_WEP_CNT) & (1 << 15))) {
        uint32_t wep_fcs = (slot->addr + 0xC + slot->length - 7) & ~1u;
        RAM16(wep_fcs) = 0x4466;
        RAM16(wep_fcs + 2) = 0x2233;
    }

    len = slot->length;
    if (slot->addr + len > 0x1FF4)
        len = 0x1FF4 - slot->addr;
    if (12 + len > (int)sizeof(tx_buffer))
        len = sizeof(tx_buffer) - 12;
    memcpy(tx_buffer, &ram[slot->addr], 12 + len);

    if (noseqno == 2)
        *(uint16_t *)&tx_buffer[0xC] |= 1 << 11;
    tx_buffer[9] = AP_CHANNEL;

    if (num == 0 || num == 2 || num == 3)
        ap_send(tx_buffer, 12 + len);
}

static void start_tx_loc(int nslot, int loc)
{
    tx_slot *slot = &tx_slots[nslot];

    slot->valid = 1;
    slot->addr = (REG(W_TXBUF_LOC1 + loc * 4) & 0x0FFF) << 1;
    slot->length = RAM16(slot->addr + 0xA) & 0x3FFF;
    slot->rate = ram[slot->addr + 8] == 0x14 ? 2 : 1;
    slot->phase = 0;
    slot->phase_time = preamble_len(slot->rate);
}

static void start_tx_beacon(void)
{
    tx_slot *slot = &tx_slots[4];

    slot->valid = 1;
    slot->addr = (REG(W_TXBUF_BEACON) & 0x0FFF) << 1;
    slot->length = RAM16(slot->addr + 0xA) & 0x3FFF;
    slot->rate = ram[slot->addr + 8] == 0x14 ? 2 : 1;
    slot->phase = 0;
    slot->phase_time = preamble_len(slot->rate);

    REG(W_TXBUSY) |= 0x0010;
}

static void fire_tx(void)
{
    uint16_t txbusy, txstart = 0;

    if (!(REG(W_RXCNT) & 0x8000))
        return;

    txbusy = REG(W_TXBUSY);
    if (REG(W_TXBUF_LOC1) & 0x8000)
        txstart |= 0x0001;
    if (REG(W_TXBUF_LOC1 + 4) & 0x8000)
        txstart |= 0x0004;
    if (REG(W_TXBUF_LOC1 + 8) & 0x8000)
        txstart |= 0x0008;
    /* CMD (multiplay) transfers are not emulated. */

    txstart &= REG(W_TXREQ_READ);
    txstart &= ~txbusy;
    REG(W_TXBUSY) = txbusy | txstart;

    if (txstart & 0x0008)
        start_tx_loc(3, 2);
    else if (txstart & 0x0004)
        start_tx_loc(2, 1);
    else if (txstart & 0x0001)
        start_tx_loc(0, 0);
}

/* Returns 1 when the slot's transfer has finished. */
static int process_tx(tx_slot *slot, int num)
{
    slot->phase_time -= STEP_US;
    if (slot->phase_time > 0)
        return 0;

    if (slot->phase == 0) {
        /* preamble done */
        set_irq(7);
        set_status(3);
        slot->phase = 1;
        slot->phase_time = slot->length * (slot->rate == 2 ? 4 : 8);
        REG(W_RXTX_ADDR) = slot->addr >> 1;
        tx_send_frame(slot, num);
        return 0;
    }

    /* transmit done */
    RAM16(slot->addr) = 0x0001;
    ram[slot->addr + 5] = 0;

    REG(W_TXBUSY) &= ~(1 << num);

    if (num == 4) {
        if (REG(W_TXSTATCNT) & 0x8000) {
            REG(W_TXSTAT) = 0x0301;
            set_irq(1);
        }
    } else {
        int loc = num ? num - 1 : 0;

        REG(W_TXSTAT) = 0x0001 | (loc << 12);
        set_irq(1);
        REG(W_TXBUF_LOC1 + loc * 4) &= 0x7FFF;
    }

    set_status(1);
    fire_tx();
    return 1;
}

/* ---- receive ---- */

static void increment_rx_addr(uint16_t *addr, int inc)
{
    int i;

    for (i = 0; i < inc; i += 2) {
        *addr = (*addr + 2) & 0x1FFE;
        if (*addr == (REG(W_RXBUF_END) & 0x1FFE))
            *addr = REG(W_RXBUF_BEGIN) & 0x1FFE;
    }
}

static void start_rx(void)
{
    uint16_t framelen = *(uint16_t *)&rx_buffer[8];
    uint16_t addr;

    rx_time = framelen * (*(uint16_t *)&rx_buffer[6] == 0x14 ? 4 : 8);

    addr = REG(W_RXBUF_WRCSR) << 1;
    increment_rx_addr(&addr, 12);
    REG(W_RXTX_ADDR) = addr >> 1;

    set_irq(6);
    set_status(6);
    com_status |= 1;
}

/*
 * Copy the received frame into the RX ring. melonDS does this one halfword at
 * a time while receiving; doing it at the end is equivalent for software that
 * only looks at completed frames. Returns 0 if the ring overflowed.
 */
static int copy_rx_frame(void)
{
    uint16_t framelen = *(uint16_t *)&rx_buffer[8];
    uint16_t addr = REG(W_RXTX_ADDR) << 1;
    int i;

    for (i = 0; i < framelen; i += 2) {
        if (addr < 0x1FFF)
            RAM16(addr) = *(uint16_t *)&rx_buffer[12 + i];
        increment_rx_addr(&addr, 2);
        if (addr == (REG(W_RXBUF_READCSR) << 1) && i + 2 < framelen)
            return 0;
    }
    REG(W_RXTX_ADDR) = addr >> 1;
    return 1;
}

static void finish_rx(void)
{
    uint16_t framectl, rxflags = 0x0010;
    const uint8_t *dst;
    uint16_t headeraddr, addr;

    com_status &= ~1;
    rx_counter = 0;

    if (!com_status) {
        if (REG(W_POWERSTATE) & (1 << 9)) {
            REG(W_TRX_POWER) = 0;
            set_status(9);
        } else {
            set_status(1);
        }
    }

    framectl = *(uint16_t *)&rx_buffer[12];

    /* The hardware always checks the first address field. */
    dst = &rx_buffer[12 + 4];
    if (!(dst[0] & 1) && !mac_equal(dst, wifi_mac()))
        return;

    if ((framectl & (1 << 14)) && !(REG(W_WEP_CNT) & (1 << 15)))
        return;

    switch ((framectl >> 2) & 3) {
    case 0: { /* management */
        uint16_t subtype = (framectl >> 4) & 0xF;

        if (mac_equal(&rx_buffer[12 + 16], (const uint8_t *)&REG(W_BSSID0)))
            rxflags |= 0x8000;

        if (subtype == 0x8) {
            if (!(rxflags & 0x8000) && !(REG(W_RXFILTER) & 1))
                return;
            rxflags |= 0x0001;
        } else if (subtype <= 0x5 || (subtype >= 0xA && subtype <= 0xC)) {
            if (!(rxflags & 0x8000) && !(REG(W_RXFILTER) & (3 << 9)))
                return;
        }
        break;
    }
    case 1: /* control: only PS-poll is passed */
        if ((framectl & 0xF0) != 0xA0)
            return;
        if (mac_equal(&rx_buffer[12 + 4], (const uint8_t *)&REG(W_BSSID0)))
            rxflags |= 0x8000;
        if (!(rxflags & 0x8000) && !(REG(W_RXFILTER) & (1 << 11)))
            return;
        rxflags |= 0x0005;
        break;
    case 2: { /* data */
        static const int bssid_offset[4] = { 16, 4, 10, 0 };
        uint16_t fromto = (framectl >> 8) & 3;
        uint16_t rxfilter = REG(W_RXFILTER);

        if (REG(W_RXFILTER2) & (1 << fromto))
            return;
        if (bssid_offset[fromto] &&
            mac_equal(&rx_buffer[12 + bssid_offset[fromto]], (const uint8_t *)&REG(W_BSSID0)))
            rxflags |= 0x8000;
        if (!(rxflags & 0x8000) && !(rxfilter & (1 << 11)))
            return;
        if ((framectl & (1 << 11)) && !(rxfilter & 1))
            return;
        rxflags |= 0x0008;

        switch ((framectl >> 4) & 0xF) {
        case 0x0:
        case 0x4:
            break;
        case 0x1: if (!(rxfilter & (1 << 1))) return; break;
        case 0x2: if (!(rxfilter & (1 << 2))) return; break;
        case 0x3: if (!(rxfilter & (1 << 3))) return; break;
        case 0x5: if (!(rxfilter & (1 << 4))) return; break;
        case 0x6: if (!(rxfilter & (1 << 5))) return; break;
        case 0x7: if (!(rxfilter & (1 << 6))) return; break;
        default: return;
        }
        break;
    }
    default:
        return;
    }

    if (!copy_rx_frame()) {
        if (log_level >= 1)
            log_line("wifi: RX buffer full, frame dropped");
        return;
    }

    /* RX header */
    headeraddr = REG(W_RXBUF_WRCSR) << 1;
    RAM16(headeraddr) = rxflags;
    increment_rx_addr(&headeraddr, 2);
    RAM16(headeraddr) = 0x0040;
    increment_rx_addr(&headeraddr, 4);
    RAM16(headeraddr) = *(uint16_t *)&rx_buffer[6];   /* rate */
    increment_rx_addr(&headeraddr, 2);
    RAM16(headeraddr) = *(uint16_t *)&rx_buffer[8];   /* length */
    increment_rx_addr(&headeraddr, 2);
    RAM16(headeraddr) = 0x4080;                       /* RSSI */

    addr = REG(W_RXTX_ADDR) << 1;
    if (addr & 2)
        increment_rx_addr(&addr, 2);
    REG(W_RXBUF_WRCSR) = (addr & ~3) >> 1;

    set_irq(0);

    /* A beacon from our BSS syncs W_US_COUNT to its timestamp. */
    if ((rxflags & 0x800F) == 0x8001) {
        uint32_t len = *(uint16_t *)&rx_buffer[8] *
                       (*(uint16_t *)&rx_buffer[6] == 0x14 ? 4 : 8);
        uint64_t ts;

        memcpy(&ts, &rx_buffer[12 + 24], 8);
        us_counter = ts + len - 76;
    }
}

static int check_rx(void)
{
    int rxlen, framelen;
    uint16_t framectl, crop;

    if (REG(W_POWERSTATE) & (1 << 9))
        return 0;
    if (!(REG(W_RXCNT) & 0x8000))
        return 0;
    if (REG(W_RXBUF_BEGIN) == REG(W_RXBUF_END))
        return 0;

    for (;;) {
        rxlen = ap_recv(rx_buffer);
        if (rxlen <= 0)
            return 0;
        if (rxlen < 12 + 24)
            continue;
        framelen = *(uint16_t *)&rx_buffer[10];
        if (framelen != rxlen - 12)
            continue;
        break;
    }

    framectl = *(uint16_t *)&rx_buffer[12];
    crop = REG(W_RXLEN_CROP);
    if (framectl & (1 << 14)) {
        framelen -= (crop >> 7) & 0x1FE;
        if (framelen > 24)
            memmove(&rx_buffer[12 + 24], &rx_buffer[12 + 28], framelen);
    } else {
        framelen -= (crop << 1) & 0x1FE;
    }
    if (framelen < 0)
        framelen = 0;

    *(uint16_t *)&rx_buffer[6] = rx_buffer[8];   /* rate */
    *(uint16_t *)&rx_buffer[8] = framelen;

    start_rx();
    return 1;
}

/* ---- timers ---- */

static void ms_timer(void)
{
    if (REG(W_US_COMPARECNT) && (us_counter & ~(uint64_t)0x3FF) == us_compare) {
        block_beacon_irq14 = 0;
        set_irq14(0);
    }

    if (REG(W_BEACON_COUNT) != 0) {
        REG(W_BEACON_COUNT)--;
        if (REG(W_BEACON_COUNT) == 0)
            set_irq14(1);
    }
    if (REG(W_BEACON_COUNT) == 0)
        REG(W_BEACON_COUNT) = REG(W_BEACONINT);

    if (REG(W_POST_BEACON) != 0) {
        REG(W_POST_BEACON)--;
        if (REG(W_POST_BEACON) == 0)
            set_irq13();
    }
}

static void us_timer(void)
{
    us_timestamp += STEP_US;

    if (!(us_timestamp & 0x3FF & STEP_MASK))
        ap_ms_timer();

    if (us_until_power_on < 0) {
        us_until_power_on += STEP_US;
        if (us_until_power_on >= 0) {
            us_until_power_on = 0;
            REG(W_POWERSTATE) = 0;
            set_status(1);
            update_power_status(0);
        }
    }

    if (REG(W_US_COUNTCNT)) {
        uint32_t uspart;

        us_counter += STEP_US;
        uspart = us_counter & 0x3FF;

        if (REG(W_US_COMPARECNT)) {
            uint32_t beaconus = ((uint32_t)REG(W_BEACON_COUNT) << 10) | (0x3FF - uspart);
            if ((beaconus & STEP_MASK) == (REG(W_PRE_BEACON) & STEP_MASK))
                set_irq15();
        }
        if (!(uspart & STEP_MASK))
            ms_timer();
    }

    if ((REG(W_CMD_COUNTCNT) & 1) && cmd_counter > 0)
        cmd_counter = cmd_counter < STEP_US ? 0 : cmd_counter - STEP_US;

    if (REG(W_CONTENTFREE) != 0)
        REG(W_CONTENTFREE) = REG(W_CONTENTFREE) < STEP_US ? 0 : REG(W_CONTENTFREE) - STEP_US;

    if (com_status == 0) {
        uint16_t txbusy = REG(W_TXBUSY);

        if (txbusy) {
            if (REG(W_POWERSTATE) & (1 << 9)) {
                tx_cur = -1;
            } else {
                com_status = 2;
                if (txbusy & 0x0010) tx_cur = 4;
                else if (txbusy & 0x0008) tx_cur = 3;
                else if (txbusy & 0x0004) tx_cur = 2;
                else tx_cur = 0;
            }
        } else {
            if (!(rx_counter & 0x1FF & STEP_MASK))
                check_rx();
            rx_counter += STEP_US;
        }
    }

    if ((com_status & 2) && tx_cur >= 0) {
        if (process_tx(&tx_slots[tx_cur], tx_cur)) {
            uint16_t txbusy;

            if (REG(W_POWERSTATE) & (1 << 9)) {
                REG(W_TXBUSY) = 0;
                REG(W_TRX_POWER) = 0;
                set_status(9);
            }

            txbusy = REG(W_TXBUSY);
            if (txbusy & 0x0010) tx_cur = 4;
            else if (txbusy & 0x0008) tx_cur = 3;
            else if (txbusy & 0x0004) tx_cur = 2;
            else if (txbusy & 0x0001) tx_cur = 0;
            else {
                tx_cur = -1;
                com_status = 0;
                rx_counter = 0;
            }
        }
    }

    if (com_status & 1) {
        rx_time -= STEP_US;
        if (rx_time <= 0)
            finish_rx();
    }
}

void wifi_advance(uint32_t us)
{
    /* W_POWER_US bit0 stops the 22MHz clock, and with it everything here. */
    if (REG(W_POWER_US) & 1)
        return;

    us += step_remainder;
    while (us >= STEP_US) {
        us_timer();
        us -= STEP_US;
    }
    step_remainder = us;
}

/* ---- RF chip (RF2958, "type 2"): registers are only stored. ---- */

static void rf_transfer(void)
{
    uint32_t id = (REG(W_RF_DATA2) >> 2) & 0x1F;

    if (REG(W_RF_DATA2) & 0x0080) {
        uint32_t data = rf_regs[id];
        REG(W_RF_DATA1) = data & 0xFFFF;
        REG(W_RF_DATA2) = (REG(W_RF_DATA2) & 0xFFFC) | ((data >> 16) & 3);
    } else {
        rf_regs[id] = REG(W_RF_DATA1) | ((uint32_t)(REG(W_RF_DATA2) & 3) << 16);
    }
}

/* ---- register access ---- */

uint16_t wifi_read16(uint32_t off)
{
    if (off >= 0x10000)
        return 0;
    off &= 0x7FFE;

    if (off >= 0x4000 && off < 0x6000)
        return RAM16(off);
    if (off >= 0x2000 && off < 0x4000)
        return 0xFFFF;

    switch (off) {
    case W_RANDOM:
        random_val = (random_val & 1) ^ (((random_val & 0x3FF) << 1) | (random_val >> 10));
        return random_val;

    case W_PREAMBLE:
        return REG(W_PREAMBLE) & 3;

    case W_US_COUNT0: return us_counter & 0xFFFF;
    case W_US_COUNT0 + 2: return (us_counter >> 16) & 0xFFFF;
    case W_US_COUNT0 + 4: return (us_counter >> 32) & 0xFFFF;
    case W_US_COUNT0 + 6: return us_counter >> 48;

    case W_US_COMPARE0: return us_compare & 0xFFFF;
    case W_US_COMPARE0 + 2: return (us_compare >> 16) & 0xFFFF;
    case W_US_COMPARE0 + 4: return (us_compare >> 32) & 0xFFFF;
    case W_US_COMPARE0 + 6: return us_compare >> 48;

    case W_CMD_COUNT:
        return (cmd_counter + 9) / 10;

    case W_BB_READ:
        if ((REG(W_BB_CNT) & 0xF000) != 0x6000)
            return 0;
        return bb_regs[REG(W_BB_CNT) & 0xFF];

    case W_BB_BUSY:
    case W_RF_BUSY:
        return 0;

    case W_RXBUF_RD_DATA: {
        uint32_t rdaddr = REG(W_RXBUF_RD_ADDR);
        uint16_t ret = RAM16(rdaddr);

        rdaddr += 2;
        if (rdaddr == (REG(W_RXBUF_END) & 0x1FFEu))
            rdaddr = REG(W_RXBUF_BEGIN) & 0x1FFE;
        if (rdaddr == REG(W_RXBUF_GAP)) {
            rdaddr += REG(W_RXBUF_GAPDISP) << 1;
            if (rdaddr >= (REG(W_RXBUF_END) & 0x1FFEu))
                rdaddr = rdaddr + (REG(W_RXBUF_BEGIN) & 0x1FFE) - (REG(W_RXBUF_END) & 0x1FFE);
        }
        REG(W_RXBUF_RD_ADDR) = rdaddr & 0x1FFE;
        REG(W_RXBUF_RD_DATA) = ret;

        if (REG(W_RXBUF_COUNT) > 0) {
            REG(W_RXBUF_COUNT)--;
            if (REG(W_RXBUF_COUNT) == 0)
                set_irq(9);
        }
        return ret;
    }

    case W_TXBUSY:
        return REG(W_TXBUSY) & 0x001F;
    }

    /* Statistics counters reset on read. */
    if ((off >= 0x1B0 && off < 0x1C6) || (off >= W_CMD_STAT0 && off < W_CMD_STAT0 + 0x10)) {
        uint16_t ret = REG(off);
        REG(off) = 0;
        return ret;
    }

    return REG(off);
}

void wifi_write16(uint32_t off, uint16_t val)
{
    if (off >= 0x10000)
        return;
    off &= 0x7FFE;

    if (off >= 0x4000 && off < 0x6000) {
        RAM16(off) = val;
        return;
    }
    if (off >= 0x2000 && off < 0x4000)
        return;
    off &= 0xFFF;

    switch (off) {
    case W_MODE_RST: {
        uint16_t oldval = REG(W_MODE_RST);

        REG(W_MODE_RST) = val & 1;
        if (!(oldval & 1) && (val & 1)) {
            REG(0x27C) = 0x0005;
            update_power_status(0);
        } else if ((oldval & 1) && !(val & 1)) {
            REG(0x27C) = 0x000A;
            update_power_status(0);
        }
        if (val & 0x2000) {
            REG(W_RXBUF_WR_ADDR) = 0;
            REG(W_CMD_TOTALTIME) = 0;
            REG(W_CMD_REPLYTIME) = 0;
            REG(0x1A4) = 0;
            REG(0x278) = 0x000F;
        }
        if (val & 0x4000) {
            REG(W_MODE_WEP) = 0;
            REG(W_TXSTATCNT) = 0;
            REG(0x00A) = 0;
            memset(&REG(W_MACADDR0), 0, 6);
            memset(&REG(W_BSSID0), 0, 6);
            REG(W_AID_LOW) = 0;
            REG(W_AID_FULL) = 0;
            REG(0x02C) = 0x0707;
            REG(0x02E) = 0;
            REG(W_RXBUF_BEGIN) = 0x4000;
            REG(W_RXBUF_END) = 0x4800;
            REG(0x084) = 0;
            REG(W_PREAMBLE) = 0x0001;
            REG(W_RXFILTER) = 0x0401;
            REG(0x0D4) = 0x0001;
            REG(W_RXFILTER2) = 0x0008;
            REG(0x0EC) = 0x3F03;
            REG(W_TX_HDR_CNT) = 0;
            REG(0x198) = 0;
            REG(0x1A2) = 0x0001;
            REG(0x224) = 0x0003;
            REG(0x230) = 0x0047;
        }
        return;
    }

    case W_MODE_WEP:
        val &= 0x007F;
        REG(W_MODE_WEP) = val;
        if (REG(W_POWER_TX) & 2) {
            if ((val & 7) == 1)
                REG(W_POWERDOWNCTRL) |= 2;
            else if ((val & 7) == 2)
                REG(W_POWERDOWNCTRL) = 3;
            if ((val & 7) != 3)
                REG(W_POWERSTATE) &= 0x0300;
            update_power_status(0);
        }
        return;

    case W_IE: {
        uint16_t oldflags = REG(W_IF) & REG(W_IE);
        REG(W_IE) = val;
        check_irq(oldflags);
        return;
    }
    case W_IF:
        REG(W_IF) &= ~val;
        return;
    case W_IF_SET: {
        uint16_t oldflags = REG(W_IF) & REG(W_IE);
        REG(W_IF) |= val & 0xFBFF;
        check_irq(oldflags);
        return;
    }

    case W_AID_LOW:
        REG(W_AID_LOW) = val & 0x000F;
        return;
    case W_AID_FULL:
        REG(W_AID_FULL) = val & 0x07FF;
        return;

    case W_POWER_US:
        REG(W_POWER_US) = val & 3;
        return;

    case W_POWER_TX:
        REG(W_POWER_TX) = val & 3;
        if (val & 2) {
            if ((REG(W_MODE_WEP) & 7) == 1)
                REG(W_POWERDOWNCTRL) |= 2;
            else if ((REG(W_MODE_WEP) & 7) == 2)
                REG(W_POWERDOWNCTRL) = 3;
            update_power_status(0);
        }
        return;

    case W_POWERSTATE:
        if ((REG(W_MODE_WEP) & 7) != 3)
            return;
        val = (REG(W_POWERSTATE) & 0x0300) | (val & 3);
        if ((val & 0x0300) == 0x0200)
            val &= ~1;
        else
            val &= ~2;
        if (!(val & (1 << 9)))
            val &= ~(1 << 8);
        REG(W_POWERSTATE) = val;
        update_power_status(0);
        return;

    case W_POWERFORCE:
        REG(W_POWERFORCE) = val & 0x8001;
        update_power_status(0);
        return;

    case W_POWERDOWNCTRL:
        REG(W_POWERDOWNCTRL) = val & 3;
        if (REG(W_POWER_TX) & 2) {
            if ((REG(W_MODE_WEP) & 7) == 1)
                REG(W_POWERDOWNCTRL) |= 2;
            else if ((REG(W_MODE_WEP) & 7) == 2)
                REG(W_POWERDOWNCTRL) = 3;
        }
        update_power_status(0);
        return;

    case W_US_COUNTCNT:
        val &= 1;
        break;
    case W_US_COMPARECNT:
        if (val & 2)
            set_irq14(2);
        val &= 1;
        break;

    case W_US_COUNT0:
        us_counter = (us_counter & 0xFFFFFFFFFFFF0000ull) | val;
        return;
    case W_US_COUNT0 + 2:
        us_counter = (us_counter & 0xFFFFFFFF0000FFFFull) | ((uint64_t)val << 16);
        return;
    case W_US_COUNT0 + 4:
        us_counter = (us_counter & 0xFFFF0000FFFFFFFFull) | ((uint64_t)val << 32);
        return;
    case W_US_COUNT0 + 6:
        us_counter = (us_counter & 0x0000FFFFFFFFFFFFull) | ((uint64_t)val << 48);
        return;

    case W_US_COMPARE0:
        us_compare = (us_compare & 0xFFFFFFFFFFFF0000ull) | (val & 0xFC00);
        if (val & 1)
            block_beacon_irq14 = 1;
        return;
    case W_US_COMPARE0 + 2:
        us_compare = (us_compare & 0xFFFFFFFF0000FFFFull) | ((uint64_t)val << 16);
        return;
    case W_US_COMPARE0 + 4:
        us_compare = (us_compare & 0xFFFF0000FFFFFFFFull) | ((uint64_t)val << 32);
        return;
    case W_US_COMPARE0 + 6:
        us_compare = (us_compare & 0x0000FFFFFFFFFFFFull) | ((uint64_t)val << 48);
        return;

    case W_CMD_COUNT:
        cmd_counter = val * 10;
        return;

    case W_BB_CNT:
        REG(W_BB_CNT) = val;
        if ((val & 0xF000) == 0x5000 && !bb_ro[val & 0xFF])
            bb_regs[val & 0xFF] = REG(W_BB_WRITE) & 0xFF;
        return;

    case W_RF_DATA2:
        REG(W_RF_DATA2) = val;
        rf_transfer();
        return;
    case W_RF_CNT:
        val &= 0x413F;
        break;

    case W_RXCNT:
        if (val & 0x0001)
            REG(W_RXBUF_WRCSR) = REG(W_RXBUF_WR_ADDR);
        if (val & 0x0080) {
            REG(W_TXBUF_REPLY2) = REG(W_TXBUF_REPLY1);
            REG(W_TXBUF_REPLY1) = 0;
        }
        val &= 0xFF0E;
        REG(W_RXCNT) = val;
        if (val & 0x8000)
            fire_tx();
        return;

    case W_RXBUF_RD_DATA:
        if (REG(W_RXBUF_COUNT) > 0) {
            REG(W_RXBUF_COUNT)--;
            if (REG(W_RXBUF_COUNT) == 0)
                set_irq(9);
        }
        return;

    case W_RXBUF_RD_ADDR:
    case W_RXBUF_GAP:
        val &= 0x1FFE;
        break;
    case W_RXBUF_GAPDISP:
    case W_RXBUF_COUNT:
    case W_RXBUF_WR_ADDR:
    case W_RXBUF_READCSR:
        val &= 0x0FFF;
        break;

    case W_TXREQ_RESET:
        REG(W_TXREQ_READ) &= ~val;
        return;
    case W_TXREQ_SET:
        REG(W_TXREQ_READ) |= val;
        fire_tx();
        return;

    case W_TXBUF_RESET:
        if (val & 0x0001) REG(W_TXBUF_LOC1) &= 0x7FFF;
        if (val & 0x0002) REG(W_TXBUF_CMD) &= 0x7FFF;
        if (val & 0x0004) REG(W_TXBUF_LOC1 + 4) &= 0x7FFF;
        if (val & 0x0008) REG(W_TXBUF_LOC1 + 8) &= 0x7FFF;
        if (val & 0x0040) REG(W_TXBUF_REPLY2) &= 0x7FFF;
        if (val & 0x0080) REG(W_TXBUF_REPLY1) &= 0x7FFF;
        return;

    case W_TXBUF_WR_DATA: {
        uint32_t wraddr = REG(W_TXBUF_WR_ADDR);

        RAM16(wraddr) = val;
        wraddr += 2;
        if (wraddr == REG(W_TXBUF_GAP))
            wraddr += REG(W_TXBUF_GAPDISP) << 1;
        REG(W_TXBUF_WR_ADDR) = wraddr & 0x1FFE;

        if (REG(W_TXBUF_COUNT) > 0) {
            REG(W_TXBUF_COUNT)--;
            if (REG(W_TXBUF_COUNT) == 0)
                set_irq(8);
        }
        return;
    }

    case W_TXBUF_WR_ADDR:
    case W_TXBUF_GAP:
        val &= 0x1FFE;
        break;
    case W_TXBUF_GAPDISP:
    case W_TXBUF_COUNT:
        val &= 0x0FFF;
        break;

    case W_MACADDR0 + 4:
        REG(off) = val;
        if (memcmp(wifi_mac(), dummy_mac, 6) == 0)
            log_line("WARNING: the firmware still has DraStic's dummy MAC 00:01:02:03:04:05, "
                     "which Wiimmfi refuses. Delete DraStic/system/nds_firmware_modified.bin "
                     "(then set up the WFC connection again).");
        return;

    case W_TXBUF_LOC1:
    case W_TXBUF_LOC1 + 4:
    case W_TXBUF_LOC1 + 8:
        REG(off) = val;
        fire_tx();
        return;

    /* read-only */
    case W_ID:
    case W_TRX_POWER:
    case W_RANDOM:
    case W_RXBUF_WRCSR:
    case W_TXBUF_REPLY2:
    case W_TXREQ_READ:
    case W_TXBUSY:
    case W_TXSTAT:
    case W_BB_READ:
    case W_BB_BUSY:
    case W_RF_BUSY:
    case W_RF_PINS:
    case 0x1A8:
    case 0x1AC:
    case 0x1C4:
    case W_TX_SEQNO:
    case W_RF_STATUS:
    case W_RXTX_ADDR:
        return;
    }

    REG(off) = val;
}
