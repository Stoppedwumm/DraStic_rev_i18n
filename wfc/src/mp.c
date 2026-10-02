/*
 * Local multiplayer transport between DraStic instances over UDP.
 * Follows the semantics of melonDS's LAN backend (net/LAN.cpp, Copyright
 * 2016-2025 melonDS team, GPLv3): unsequenced frames with a sender ID, type and
 * timestamp; blocking receives with a 25 ms timeout for host frames and
 * replies, which is what keeps the consoles in lockstep.
 *
 * Copyright (C) 2026 DraStic_rev_i18n contributors
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version. See wfc/LICENSE.
 *
 * Discovery: each instance binds the first free UDP port in MP_PORT_FIRST..
 * MP_PORT_LAST and announces itself every 500 ms to every port of that range on
 * 127.0.0.1 (several instances on one device) and on the broadcast address
 * (other devices on the same network). Peers that stay silent for 3 s are
 * dropped. Runs entirely on the emulation thread.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "wfc.h"

#define MP_PORT_FIRST 7064
#define MP_PORT_LAST  7071
#define MP_MAGIC      0x504D5344u   /* "DSMP" */
#define MP_HELLO      0x100u
#define MAX_PEERS     15
#define HELLO_MS      500
#define PEER_TIMEOUT_MS 3000
#define RECV_TIMEOUT_MS 25
#define STALE_MS      16
#define QUEUE_LEN     64
#define MAX_FRAME     2048

typedef struct {
    uint32_t magic;
    uint32_t sender;
    uint32_t type;      /* 0 packet, 1 cmd, 2|aid<<16 reply, 3 ack, MP_HELLO */
    uint32_t length;
    uint64_t timestamp;
} mp_header;

typedef struct {
    struct sockaddr_in addr;
    uint32_t id;
    uint32_t last_seen_ms;
    int active;          /* its wifi is powered (melonDS: Begin/End) */
    int used;
} mp_peer;

typedef struct {
    uint32_t recv_ms;
    int peer;
    mp_header hdr;
    uint8_t data[MAX_FRAME];
} rx_entry;

static int sock = -1;
static int my_port;
static uint32_t my_id;
static int my_active;
static uint32_t last_hello_ms;
static mp_peer peers[MAX_PEERS];
static int last_host = -1;
static rx_entry rxq[QUEUE_LEN];
static int rxq_head, rxq_count;

static uint32_t ms_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static int peer_alive(int i)
{
    return peers[i].used && peers[i].active && ms_now() - peers[i].last_seen_ms < PEER_TIMEOUT_MS;
}

static int alive_count(void)
{
    int i, n = 0;

    for (i = 0; i < MAX_PEERS; i++)
        n += peer_alive(i);
    return n;
}

static void send_to(const struct sockaddr_in *sa, const void *buf, int len)
{
    sendto(sock, buf, len, 0, (const struct sockaddr *)sa, sizeof(*sa));
}

static void send_hello(void)
{
    mp_header h;
    struct sockaddr_in sa;
    int port;

    h.magic = MP_MAGIC;
    h.sender = my_id;
    h.type = MP_HELLO;
    h.length = my_active;
    h.timestamp = 0;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    for (port = MP_PORT_FIRST; port <= MP_PORT_LAST; port++) {
        sa.sin_port = htons(port);
        if (port != my_port) {
            sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            send_to(&sa, &h, sizeof(h));
        }
        sa.sin_addr.s_addr = htonl(INADDR_BROADCAST);
        send_to(&sa, &h, sizeof(h));
    }
    last_hello_ms = ms_now();
}

static int peer_lookup(const struct sockaddr_in *sa, uint32_t id, int create)
{
    int i, free_slot = -1;

    for (i = 0; i < MAX_PEERS; i++) {
        if (peers[i].used && peers[i].id == id) {
            /* Prefer loopback when a peer is reachable both ways. */
            if (sa->sin_addr.s_addr == htonl(INADDR_LOOPBACK) ||
                peers[i].addr.sin_addr.s_addr != htonl(INADDR_LOOPBACK))
                peers[i].addr = *sa;
            return i;
        }
        if (!peers[i].used && free_slot < 0)
            free_slot = i;
        else if (peers[i].used && ms_now() - peers[i].last_seen_ms > 10 * PEER_TIMEOUT_MS && free_slot < 0)
            free_slot = i;
    }
    if (!create || free_slot < 0)
        return -1;

    memset(&peers[free_slot], 0, sizeof(peers[free_slot]));
    peers[free_slot].used = 1;
    peers[free_slot].id = id;
    peers[free_slot].addr = *sa;
    if (log_level >= 1)
        log_line("mp: found DraStic peer %08x at %s:%u", id, inet_ntoa(sa->sin_addr),
                 ntohs(sa->sin_port));
    return free_slot;
}

/*
 * Read one datagram. Returns 1 if a frame was queued, 0 otherwise (nothing
 * pending, a hello, or junk).
 */
static int read_one(void)
{
    static uint8_t buf[sizeof(mp_header) + MAX_FRAME];
    struct sockaddr_in sa;
    socklen_t salen = sizeof(sa);
    mp_header h;
    rx_entry *e;
    int n, p;

    n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&sa, &salen);
    if (n < (int)sizeof(mp_header))
        return n < 0 ? -1 : 0;
    memcpy(&h, buf, sizeof(h));
    if (h.magic != MP_MAGIC || h.sender == my_id)
        return 0;

    p = peer_lookup(&sa, h.sender, 1);
    if (p < 0)
        return 0;
    peers[p].last_seen_ms = ms_now();

    if (h.type == MP_HELLO) {
        if (peers[p].active != (int)h.length && log_level >= 1)
            log_line("mp: peer %08x wifi %s", h.sender, h.length ? "on" : "off");
        peers[p].active = h.length;
        return 0;
    }
    peers[p].active = 1;

    if (h.length > MAX_FRAME || (int)(sizeof(h) + h.length) > n)
        return 0;
    if (rxq_count == QUEUE_LEN) {
        rxq_head = (rxq_head + 1) % QUEUE_LEN;
        rxq_count--;
    }
    e = &rxq[(rxq_head + rxq_count) % QUEUE_LEN];
    e->recv_ms = ms_now();
    e->peer = p;
    e->hdr = h;
    memcpy(e->data, buf + sizeof(h), h.length);
    rxq_count++;
    return 1;
}

static void pop_front(void)
{
    rxq_head = (rxq_head + 1) % QUEUE_LEN;
    rxq_count--;
}

/* type: 0 = housekeeping, 1 = looking for a regular frame, 2 = blocking for an MP frame */
static void pump(int type)
{
    uint32_t now = ms_now(), start;
    int timeout = type == 2 ? RECV_TIMEOUT_MS : 0;

    if (sock < 0)
        return;
    if (now - last_hello_ms >= HELLO_MS)
        send_hello();

    /* Frames that sat in the queue longer than a frame's time are stale. */
    while (rxq_count) {
        rx_entry *e = &rxq[rxq_head];

        if (now - e->recv_ms > STALE_MS) {
            pop_front();
            continue;
        }
        if (type == 2)
            return;
        if (type == 1) {
            if (e->hdr.type == 0)
                return;
            pop_front();    /* an MP frame while looking for a regular one */
            continue;
        }
        break;
    }

    start = ms_now();
    for (;;) {
        int r = read_one();

        if (r > 0 && type != 0)
            return;
        if (r < 0) {
            struct pollfd pfd;
            int left = timeout - (int)(ms_now() - start);

            if (left <= 0)
                return;
            pfd.fd = sock;
            pfd.events = POLLIN;
            if (poll(&pfd, 1, left) <= 0)
                return;
        }
    }
}

static int send_generic(uint32_t type, const uint8_t *data, int len, uint64_t timestamp)
{
    static uint8_t buf[sizeof(mp_header) + MAX_FRAME];
    mp_header h;
    int i;

    if (sock < 0 || len > MAX_FRAME)
        return 0;

    h.magic = MP_MAGIC;
    h.sender = my_id;
    h.type = type;
    h.length = len;
    h.timestamp = timestamp;
    memcpy(buf, &h, sizeof(h));
    if (len)
        memcpy(buf + sizeof(h), data, len);

    if ((type & 0xFFFF) == 2 && last_host >= 0 && peers[last_host].used) {
        send_to(&peers[last_host].addr, buf, sizeof(h) + len);
    } else {
        for (i = 0; i < MAX_PEERS; i++) {
            if (peers[i].used && ms_now() - peers[i].last_seen_ms < PEER_TIMEOUT_MS)
                send_to(&peers[i].addr, buf, sizeof(h) + len);
        }
    }
    return len;
}

static int recv_generic(uint8_t *data, int block, uint64_t *timestamp)
{
    rx_entry *e;
    uint32_t len;

    if (sock < 0)
        return 0;
    pump(block ? 2 : 1);
    if (!rxq_count)
        return 0;

    e = &rxq[rxq_head];
    len = e->hdr.length;
    if (len) {
        memcpy(data, e->data, len);
        if (e->hdr.type == 1)
            last_host = e->peer;
    }
    if (timestamp)
        *timestamp = e->hdr.timestamp;
    pop_front();
    return len;
}

/* ---- API used by wifi.c ---- */

void mp_init(void)
{
    struct sockaddr_in sa;
    int one = 1, port;
    FILE *f;

    f = fopen("/dev/urandom", "r");
    if (!f || fread(&my_id, 1, sizeof(my_id), f) != sizeof(my_id))
        my_id = ms_now() ^ (uint32_t)getpid() << 16;
    if (f)
        fclose(f);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        log_line("mp: socket: %s", strerror(errno));
        return;
    }
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
    fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    for (port = MP_PORT_FIRST; port <= MP_PORT_LAST; port++) {
        sa.sin_port = htons(port);
        if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) == 0)
            break;
    }
    if (port > MP_PORT_LAST) {
        log_line("mp: no free port in %d-%d, local multiplayer disabled", MP_PORT_FIRST, MP_PORT_LAST);
        close(sock);
        sock = -1;
        return;
    }
    my_port = port;
    log_line("mp: local multiplayer id %08x on UDP port %d", my_id, my_port);
    send_hello();
}

void mp_begin(void)
{
    my_active = 1;
    last_host = -1;
    if (sock >= 0)
        send_hello();
}

void mp_end(void)
{
    my_active = 0;
    if (sock >= 0)
        send_hello();
}

void mp_poll(void)
{
    pump(0);
}

int mp_send_packet(const uint8_t *data, int len, uint64_t timestamp)
{
    return send_generic(0, data, len, timestamp);
}

int mp_send_cmd(const uint8_t *data, int len, uint64_t timestamp)
{
    return send_generic(1, data, len, timestamp);
}

int mp_send_reply(const uint8_t *data, int len, uint64_t timestamp, uint16_t aid)
{
    return send_generic(2 | ((uint32_t)aid << 16), data, len, timestamp);
}

int mp_send_ack(const uint8_t *data, int len, uint64_t timestamp)
{
    return send_generic(3, data, len, timestamp);
}

int mp_recv_packet(uint8_t *data, uint64_t *timestamp)
{
    return recv_generic(data, 0, timestamp);
}

int mp_recv_host_packet(uint8_t *data, uint64_t *timestamp)
{
    /* Report the host as gone once it stops announcing itself. */
    if (last_host >= 0 && !peer_alive(last_host))
        return -1;
    return recv_generic(data, 1, timestamp);
}

uint16_t mp_recv_replies(uint8_t *packets, uint64_t timestamp, uint16_t aidmask)
{
    uint16_t ret = 0;
    int replied[MAX_PEERS] = { 0 };
    int expected = alive_count(), got = 0;

    if (sock < 0 || expected == 0)
        return 0;

    for (;;) {
        rx_entry *e;
        int good = 1;

        pump(2);
        if (!rxq_count)
            return ret;   /* timed out: the rest failed to reply */

        e = &rxq[rxq_head];
        if ((e->hdr.type & 0xFFFF) != 2)
            good = 0;
        else if (e->hdr.timestamp < timestamp - 32)
            good = 0;   /* stale reply to an earlier CMD */

        if (good) {
            uint32_t aid = e->hdr.type >> 16;
            uint32_t len = e->hdr.length;

            if (len && aid >= 1 && aid <= 15) {
                if (len > 1024)
                    len = 1024;
                memcpy(&packets[(aid - 1) * 1024], e->data, len);
                ret |= 1 << aid;
            }
            if (!replied[e->peer]) {
                replied[e->peer] = 1;
                got++;
            }
            if (got >= expected || (ret & aidmask) == aidmask) {
                pop_front();
                return ret;
            }
        }
        pop_front();
    }
}
