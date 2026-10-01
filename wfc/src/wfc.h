/*
 * libdrastic_wfc - Nintendo Wi-Fi Connection support for DraStic (arm64).
 * Copyright (C) 2026 DraStic_rev_i18n contributors
 *
 * The wifi chip and access point emulation (wifi.c, wifi_ap.c) is a C port of
 * melonDS's Wifi.cpp / WifiAP.cpp (Copyright 2016-2025 melonDS team), so this
 * directory is distributed under the GNU General Public License v3 or later.
 * See wfc/LICENSE.
 */

#ifndef WFC_H
#define WFC_H

#include <stdint.h>

/* wfc_hook.c */
extern int log_level;
void log_line(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
/* Raise ARM7 IF bit 24 (wifi). */
void arm7_wifi_irq(void);
/* DraStic's built-in firmware MAC, 00:01:02:03:04:05. */
extern const uint8_t dummy_mac[6];

/* wifi.c - the emulated wifi chip. Offsets are relative to 0x04800000. */
void wifi_reset(void);
uint16_t wifi_read16(uint32_t off);
void wifi_write16(uint32_t off, uint16_t val);
void wifi_advance(uint32_t us);
const uint8_t *wifi_mac(void);

/* wifi_ap.c - the fake access point the chip talks to. */
#define AP_CHANNEL 6
void ap_reset(void);
void ap_ms_timer(void);
/* A frame transmitted by the console: 12-byte TX header + IEEE frame. */
void ap_send(const uint8_t *data, int len);
/* Next frame for the console (12-byte header + IEEE frame incl. FCS), or 0. */
int ap_recv(uint8_t *data);
const uint8_t *ap_bssid(void);
/* Queue an Ethernet frame for delivery to the console. */
void ap_queue_eth(const uint8_t *eth, int len);

/* net.c - NAT between the console and the internet. */
void net_init(const char *dns);
void net_reset(void);
void net_input(const uint8_t *eth, int len);
void net_poll(void);

#endif
