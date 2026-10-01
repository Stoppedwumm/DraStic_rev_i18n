/*
 * Fake wifi access point that the emulated chip talks to. C port of melonDS's
 * WifiAP.cpp (Copyright 2016-2025 melonDS team, GPLv3).
 *
 * Copyright (C) 2026 DraStic_rev_i18n contributors
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version. See wfc/LICENSE.
 *
 * Unlike melonDS, the AP answers on every channel: DraStic's built-in firmware
 * has no RF channel tables, so the selected channel cannot be decoded.
 */

#include <string.h>

#include "wfc.h"

static const char ap_name[] = "DraSticWFC";
/* Locally administered address. */
static const uint8_t ap_mac[6] = { 0x02, 0x00, 0x44, 0x57, 0x46, 0x43 };

static uint64_t ap_us_counter;
static uint16_t seq_no;
static int beacon_due;
static uint8_t packet_buffer[2048];
static int packet_len;
static int rx_pending;
/* 0 = idle, 1 = authenticated, 2 = associated */
static int client_status;

/* Ethernet frames waiting to be delivered to the console as data frames. */
#define QUEUE_LEN 64
#define QUEUE_FRAME 1600
static uint8_t queue[QUEUE_LEN][QUEUE_FRAME];
static int queue_len[QUEUE_LEN];
static int queue_head, queue_count;
static uint32_t queue_drops;

#define PUT8(p, v) (*(p)++ = (uint8_t)(v))
#define PUT16(p, v) do { uint16_t v_ = (v); memcpy((p), &v_, 2); (p) += 2; } while (0)
#define PUT32(p, v) do { uint32_t v_ = (v); memcpy((p), &v_, 4); (p) += 4; } while (0)
#define PUT64(p, v) do { uint64_t v_ = (v); memcpy((p), &v_, 8); (p) += 8; } while (0)
#define PUTMAC(p, m) do { memcpy((p), (m), 6); (p) += 6; } while (0)
#define PUTSEQ(p) do { PUT16(p, seq_no); seq_no += 0x10; } while (0)

static int mac_equal(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, 6) == 0;
}

void ap_reset(void)
{
    ap_us_counter = 0x428888000ull;
    seq_no = 0x0120;
    beacon_due = 0;
    packet_len = 0;
    rx_pending = 0;
    client_status = 0;
    queue_head = 0;
    queue_count = 0;
    net_reset();
}

const uint8_t *ap_bssid(void)
{
    return ap_mac;
}

void ap_queue_eth(const uint8_t *eth, int len)
{
    int slot;

    if (len > QUEUE_FRAME)
        return;
    if (queue_count == QUEUE_LEN) {
        if (log_level >= 1 && (++queue_drops & 63) == 1)
            log_line("ap: queue full, dropped %u frame(s)", queue_drops);
        return;
    }
    slot = (queue_head + queue_count) % QUEUE_LEN;
    memcpy(queue[slot], eth, len);
    queue_len[slot] = len;
    queue_count++;
}

void ap_ms_timer(void)
{
    ap_us_counter += 0x400;
    /* beacon every 128ms */
    if (!((uint32_t)ap_us_counter & 0x1FC00))
        beacon_due = 1;
    if (client_status == 2)
        net_poll();
}

/* Start of a management frame from the AP to the client at addr2 of `req`. */
static uint8_t *mgmt_header(uint8_t *p, uint16_t framectl, const uint8_t *req)
{
    PUT16(p, framectl);
    PUT16(p, 0);              /* duration */
    PUTMAC(p, &req[10]);      /* receiver = requesting client */
    PUTMAC(p, ap_mac);        /* sender */
    PUTMAC(p, ap_mac);        /* BSSID */
    PUTSEQ(p);
    return p;
}

static uint8_t *put_ies(uint8_t *p, int with_tim)
{
    size_t n = strlen(ap_name);

    PUT8(p, 0x00);            /* SSID */
    PUT8(p, n);
    memcpy(p, ap_name, n);
    p += n;
    PUT8(p, 0x01);            /* supported rates: 1, 2 Mbit/s (basic) */
    PUT8(p, 0x02);
    PUT8(p, 0x82);
    PUT8(p, 0x84);
    PUT8(p, 0x03);            /* DS parameter set */
    PUT8(p, 0x01);
    PUT8(p, AP_CHANNEL);
    if (with_tim) {
        PUT8(p, 0x05);        /* TIM */
        PUT8(p, 0x04);
        PUT32(p, 0);
    }
    return p;
}

static void handle_mgmt(const uint8_t *data)
{
    uint16_t framectl = data[0] | (data[1] << 8);
    uint8_t *p = packet_buffer;

    if (rx_pending) {
        if (log_level >= 1)
            log_line("ap: busy, dropping management frame %04X", framectl);
        return;
    }

    switch ((framectl >> 4) & 0xF) {
    case 0x0: /* association request */
        if (!mac_equal(&data[16], ap_mac))
            return;
        if (client_status != 1) {
            if (log_level >= 1)
                log_line("ap: association request without authentication");
            return;
        }
        client_status = 2;
        if (log_level >= 1)
            log_line("ap: client associated");
        p = mgmt_header(p, 0x0010, data);
        PUT16(p, 0x0021);     /* capability: ESS, short preamble */
        PUT16(p, 0);          /* status: success */
        PUT16(p, 0xC001);     /* association ID */
        PUT8(p, 0x01);
        PUT8(p, 0x02);
        PUT8(p, 0x82);
        PUT8(p, 0x84);
        break;

    case 0x4: /* probe request */
        if (log_level >= 1)
            log_line("ap: probe request, answering");
        p = mgmt_header(p, 0x0050, data);
        PUT64(p, ap_us_counter);
        PUT16(p, 128);        /* beacon interval */
        PUT16(p, 0x0021);
        p = put_ies(p, 0);
        break;

    case 0xA: /* disassociation */
        if (!mac_equal(&data[16], ap_mac))
            return;
        client_status = 1;
        if (log_level >= 1)
            log_line("ap: client disassociated");
        p = mgmt_header(p, 0x00A0, data);
        PUT16(p, 3);
        break;

    case 0xB: /* authentication */
        if (!mac_equal(&data[16], ap_mac))
            return;
        client_status = 1;
        if (log_level >= 1)
            log_line("ap: client authenticated");
        p = mgmt_header(p, 0x00B0, data);
        PUT16(p, 0);          /* open system */
        PUT16(p, 2);          /* sequence */
        PUT16(p, 0);          /* success */
        break;

    case 0xC: /* deauthentication */
        if (!mac_equal(&data[16], ap_mac))
            return;
        client_status = 0;
        if (log_level >= 1)
            log_line("ap: client deauthenticated");
        p = mgmt_header(p, 0x00C0, data);
        PUT16(p, 3);
        break;

    default:
        if (log_level >= 1)
            log_line("ap: unhandled management frame %04X", framectl);
        return;
    }

    packet_len = p - packet_buffer;
    rx_pending = 1;
}

void ap_send(const uint8_t *data, int len)
{
    uint16_t framectl;

    if (len < 12 + 24)
        return;
    data += 12;
    framectl = data[0] | (data[1] << 8);

    switch ((framectl >> 2) & 3) {
    case 0:
        handle_mgmt(data);
        break;
    case 2: {
        /* ToDS data frame: 802.11 header, LLC/SNAP, payload, FCS. */
        static const uint8_t snap[6] = { 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00 };
        uint8_t eth[QUEUE_FRAME];
        int flen = len - 12, plen;

        if ((framectl & 0x0300) != 0x0100 || (framectl & 0x4000) || client_status != 2)
            return;
        if ((framectl & 0xF0) != 0)
            return;   /* null/QoS-less subtypes without payload */
        plen = flen - 24 - 8 - 4;
        if (plen <= 0 || 14 + plen > (int)sizeof(eth) || memcmp(&data[24], snap, 6) != 0)
            return;
        memcpy(eth, &data[16], 6);        /* DA = addr3 */
        memcpy(eth + 6, &data[10], 6);    /* SA = addr2 */
        memcpy(eth + 12, &data[30], 2);   /* ethertype */
        memcpy(eth + 14, &data[32], plen);
        net_input(eth, 14 + plen);
        break;
    }
    }
}

/* 12-byte TX-style header in front of a frame, as the chip expects. */
static int finish_frame(uint8_t *data, uint8_t *p)
{
    uint8_t *base = data + 12;
    int len;

    while ((p - base) & 3)
        *p++ = 0xFF;
    PUT32(p, 0xDEADBEEF);     /* FCS, not checked */
    len = p - base;

    p = data;
    PUT16(p, 0);
    PUT16(p, 0);
    PUT16(p, 0);
    PUT16(p, 0);
    PUT8(p, 20);              /* 2 Mbit/s */
    PUT8(p, AP_CHANNEL);
    PUT16(p, len);
    return len + 12;
}

int ap_recv(uint8_t *data)
{
    uint8_t *p = data + 12;

    if (beacon_due) {
        static const uint8_t bcast[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

        beacon_due = 0;
        PUT16(p, 0x0080);
        PUT16(p, 0);
        PUTMAC(p, bcast);
        PUTMAC(p, ap_mac);
        PUTMAC(p, ap_mac);
        PUTSEQ(p);
        PUT64(p, ap_us_counter);
        PUT16(p, 128);
        PUT16(p, 0x0021);
        p = put_ies(p, 1);
        return finish_frame(data, p);
    }

    if (rx_pending) {
        rx_pending = 0;
        memcpy(p, packet_buffer, packet_len);
        return finish_frame(data, p + packet_len);
    }

    if (queue_count && client_status == 2) {
        const uint8_t *eth = queue[queue_head];
        int elen = queue_len[queue_head];

        queue_head = (queue_head + 1) % QUEUE_LEN;
        queue_count--;

        PUT16(p, 0x0208);         /* data, FromDS */
        PUT16(p, 0);
        PUTMAC(p, eth);           /* DA */
        PUTMAC(p, ap_mac);        /* BSSID */
        PUTMAC(p, eth + 6);       /* SA */
        PUTSEQ(p);
        PUT8(p, 0xAA);
        PUT8(p, 0xAA);
        PUT8(p, 0x03);
        PUT8(p, 0);
        PUT8(p, 0);
        PUT8(p, 0);
        memcpy(p, eth + 12, elen - 12);   /* ethertype + payload */
        p += elen - 12;
        return finish_frame(data, p);
    }

    return 0;
}
