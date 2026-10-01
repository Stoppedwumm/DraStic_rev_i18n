/*
 * Minimal user-mode NAT between the emulated console and the internet:
 * ARP, DHCP, DNS forwarding, and UDP/TCP proxying over ordinary sockets.
 *
 * Copyright (C) 2026 DraStic_rev_i18n contributors
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version. See wfc/LICENSE.
 *
 * Virtual network (like slirp): gateway 10.0.2.2, DNS 10.0.2.3, console
 * 10.0.2.15. DNS queries are forwarded to a WFC revival DNS server, which
 * redirects Nintendo's hostnames. Everything runs on the emulation thread,
 * driven by net_poll() once per emulated millisecond; sockets are non-blocking.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "wfc.h"

#define IP_GATEWAY  0x0A000202u   /* 10.0.2.2  */
#define IP_DNS      0x0A000203u   /* 10.0.2.3  */
#define IP_CLIENT   0x0A00020Fu   /* 10.0.2.15 */
#define IP_MASK     0xFFFFFF00u

#define ETH_ARP 0x0806
#define ETH_IP  0x0800

#define MAX_UDP 32
#define MAX_TCP 32
#define UDP_IDLE_MS 60000
#define TCP_MSS 1360
#define TCP_BUF 65536
#define TCP_RTO_MS 400

static uint8_t client_mac[6];
static int have_client_mac;
static uint32_t dns_server;      /* network byte order */
static uint32_t now_ms;
static uint16_t ip_id;

/* ---- helpers ---- */

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]; }
static void wr16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v; }
static void wr32(uint8_t *p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }

static uint32_t csum_add(uint32_t sum, const uint8_t *p, int len)
{
    int i;

    for (i = 0; i + 1 < len; i += 2)
        sum += rd16(p + i);
    if (len & 1)
        sum += p[len - 1] << 8;
    return sum;
}

static uint16_t csum_fold(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum & 0xFFFF;
}

/* Hex dump of the first bytes of a connection, for protocol debugging. */
static void dump_bytes(const char *dir, uint32_t offset, const uint8_t *p, int len)
{
    char line[3 * 32 + 1];
    int i, n;

    if (log_level < 1 || offset >= 128)
        return;
    if (len > (int)(128 - offset))
        len = 128 - offset;
    for (i = 0; i < len; i += 32) {
        int j;

        n = len - i < 32 ? len - i : 32;
        for (j = 0; j < n; j++)
            snprintf(line + 3 * j, 4, "%02x ", p[i + j]);
        log_line("net:   %s +%u: %s", dir, offset + i, line);
    }
}

static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* Build Ethernet + IPv4 header in front of an L4 payload already at buf+34. */
static void send_ip(uint8_t *buf, int l4len, uint8_t proto, uint32_t src, uint32_t dst)
{
    uint8_t *ip = buf + 14;
    static const uint8_t bcast[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    memcpy(buf, have_client_mac ? client_mac : bcast, 6);
    memcpy(buf + 6, ap_bssid(), 6);
    wr16(buf + 12, ETH_IP);

    ip[0] = 0x45;
    ip[1] = 0;
    wr16(ip + 2, 20 + l4len);
    wr16(ip + 4, ip_id++);
    wr16(ip + 6, 0x4000);     /* DF */
    ip[8] = 64;
    ip[9] = proto;
    wr16(ip + 10, 0);
    wr32(ip + 12, src);
    wr32(ip + 16, dst);
    wr16(ip + 10, csum_fold(csum_add(0, ip, 20)));

    ap_queue_eth(buf, 14 + 20 + l4len);
}

static uint16_t l4_csum(const uint8_t *l4, int len, uint8_t proto, uint32_t src, uint32_t dst)
{
    uint8_t pseudo[12];

    wr32(pseudo, src);
    wr32(pseudo + 4, dst);
    pseudo[8] = 0;
    pseudo[9] = proto;
    wr16(pseudo + 10, len);
    return csum_fold(csum_add(csum_add(0, pseudo, 12), l4, len));
}

static void send_udp(uint32_t src, uint16_t sport, uint32_t dst, uint16_t dport,
                     const uint8_t *data, int len)
{
    uint8_t buf[14 + 20 + 8 + 1500];
    uint8_t *udp = buf + 34;
    uint16_t c;

    if (len > 1472)
        len = 1472;
    wr16(udp, sport);
    wr16(udp + 2, dport);
    wr16(udp + 4, 8 + len);
    wr16(udp + 6, 0);
    memcpy(udp + 8, data, len);
    c = l4_csum(udp, 8 + len, 17, src, dst);
    wr16(udp + 6, c ? c : 0xFFFF);
    send_ip(buf, 8 + len, 17, src, dst);
}

/* ---- ARP ---- */

static void handle_arp(const uint8_t *eth, int len)
{
    const uint8_t *arp = eth + 14;
    uint8_t buf[14 + 28];
    uint32_t target;

    if (len < 14 + 28 || rd16(arp + 6) != 1)   /* request */
        return;
    target = rd32(arp + 24);
    if (target == IP_CLIENT || (target & IP_MASK) != (IP_CLIENT & IP_MASK))
        return;

    /* Everything in the subnet except the console is "us". */
    memcpy(buf, arp + 8, 6);
    memcpy(buf + 6, ap_bssid(), 6);
    wr16(buf + 12, ETH_ARP);
    memcpy(buf + 14, arp, 6);               /* htype, ptype, hlen, plen */
    wr16(buf + 20, 2);                      /* reply */
    memcpy(buf + 22, ap_bssid(), 6);
    wr32(buf + 28, target);
    memcpy(buf + 32, arp + 8, 10);          /* requester MAC + IP */
    ap_queue_eth(buf, sizeof(buf));
}

/* ---- DHCP ---- */

static void handle_dhcp(const uint8_t *msg, int len)
{
    uint8_t out[300];
    uint8_t *o;
    int type = 0, i;

    if (len < 240 || msg[0] != 1 || rd32(msg + 236) != 0x63825363)
        return;
    for (i = 240; i + 1 < len && msg[i] != 255;) {
        if (msg[i] == 0) {
            i++;
            continue;
        }
        if (msg[i] == 53 && msg[i + 1] >= 1)
            type = msg[i + 2];
        i += 2 + msg[i + 1];
    }
    if (type != 1 && type != 3)   /* DISCOVER, REQUEST */
        return;

    memset(out, 0, sizeof(out));
    out[0] = 2;                   /* BOOTREPLY */
    out[1] = 1;
    out[2] = 6;
    memcpy(out + 4, msg + 4, 4);  /* xid */
    memcpy(out + 10, msg + 10, 2);/* flags */
    wr32(out + 16, IP_CLIENT);    /* yiaddr */
    wr32(out + 20, IP_GATEWAY);   /* siaddr */
    memcpy(out + 28, msg + 28, 16);  /* chaddr */
    wr32(out + 236, 0x63825363);
    o = out + 240;
    *o++ = 53; *o++ = 1; *o++ = type == 1 ? 2 : 5;      /* OFFER / ACK */
    *o++ = 54; *o++ = 4; wr32(o, IP_GATEWAY); o += 4;   /* server id */
    *o++ = 51; *o++ = 4; wr32(o, 86400); o += 4;        /* lease */
    *o++ = 1;  *o++ = 4; wr32(o, IP_MASK); o += 4;
    *o++ = 3;  *o++ = 4; wr32(o, IP_GATEWAY); o += 4;
    *o++ = 6;  *o++ = 4; wr32(o, IP_DNS); o += 4;
    *o++ = 255;

    if (log_level >= 1)
        log_line("net: DHCP %s -> 10.0.2.15", type == 1 ? "discover" : "request");
    send_udp(IP_GATEWAY, 67, 0xFFFFFFFFu, 68, out, o - out);
}

/* ---- UDP ---- */

typedef struct {
    int fd;
    uint16_t cport;      /* console port */
    uint32_t last_ms;
    int is_dns;
} udp_flow;

static udp_flow udp_flows[MAX_UDP];

static udp_flow *udp_get(uint16_t cport, int is_dns)
{
    udp_flow *f, *free_slot = NULL, *oldest = NULL;
    int i;

    for (i = 0; i < MAX_UDP; i++) {
        f = &udp_flows[i];
        if (f->fd > 0 && f->cport == cport && f->is_dns == is_dns)
            return f;
        if (f->fd <= 0 && !free_slot)
            free_slot = f;
        if (f->fd > 0 && (!oldest || f->last_ms < oldest->last_ms))
            oldest = f;
    }
    if (!free_slot) {
        close(oldest->fd);
        oldest->fd = 0;
        free_slot = oldest;
    }
    f = free_slot;
    f->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (f->fd < 0) {
        log_line("net: udp socket: %s", strerror(errno));
        f->fd = 0;
        return NULL;
    }
    set_nonblock(f->fd);
    f->cport = cport;
    f->is_dns = is_dns;
    return f;
}

static void handle_udp(const uint8_t *ip, int iplen, int ihl)
{
    const uint8_t *udp = ip + ihl;
    uint32_t dst = rd32(ip + 16);
    uint16_t sport, dport, ulen;
    struct sockaddr_in sa;
    udp_flow *f;
    int is_dns;

    if (iplen < ihl + 8)
        return;
    sport = rd16(udp);
    dport = rd16(udp + 2);
    ulen = rd16(udp + 4);
    if (ulen < 8 || ihl + ulen > iplen)
        return;

    if (dport == 67) {
        handle_dhcp(udp + 8, ulen - 8);
        return;
    }
    if (dst == 0xFFFFFFFFu || (dst & 0xF0000000u) == 0xE0000000u)
        return;   /* broadcast / multicast */

    is_dns = dst == IP_DNS && dport == 53;
    f = udp_get(sport, is_dns);
    if (!f)
        return;
    f->last_ms = now_ms;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    if (is_dns) {
        sa.sin_addr.s_addr = dns_server;
        sa.sin_port = htons(53);
    } else {
        sa.sin_addr.s_addr = htonl(dst);
        sa.sin_port = htons(dport);
    }
    if (sendto(f->fd, udp + 8, ulen - 8, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0 &&
        log_level >= 1)
        log_line("net: udp sendto: %s", strerror(errno));
    else if (is_dns && log_level >= 1)
        log_line("net: DNS query forwarded");
}

static void poll_udp(void)
{
    uint8_t data[1500];
    struct sockaddr_in sa;
    socklen_t salen;
    int i, n;

    for (i = 0; i < MAX_UDP; i++) {
        udp_flow *f = &udp_flows[i];

        if (f->fd <= 0)
            continue;
        for (;;) {
            salen = sizeof(sa);
            n = recvfrom(f->fd, data, sizeof(data), 0, (struct sockaddr *)&sa, &salen);
            if (n < 0)
                break;
            f->last_ms = now_ms;
            if (f->is_dns)
                send_udp(IP_DNS, 53, IP_CLIENT, f->cport, data, n);
            else
                send_udp(ntohl(sa.sin_addr.s_addr), ntohs(sa.sin_port), IP_CLIENT, f->cport, data, n);
        }
        if (now_ms - f->last_ms > UDP_IDLE_MS) {
            close(f->fd);
            f->fd = 0;
        }
    }
}

/* ---- TCP ---- */

enum { T_FREE, T_CONNECTING, T_SYNACK_SENT, T_OPEN };

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PSH 0x08
#define TH_ACK 0x10

typedef struct {
    int state;
    int fd;
    uint32_t rip;            /* remote, host order */
    uint16_t rport, cport;
    uint32_t rcv_nxt;        /* next byte expected from the console */
    uint32_t snd_una;        /* oldest byte the console has not acked */
    uint32_t snd_nxt;        /* next byte to send */
    uint32_t snd_max;        /* highest byte sent so far (snd_nxt rewinds on retransmit) */
    uint32_t iss;
    uint16_t cwnd;           /* console's advertised window */
    uint16_t mss;
    uint8_t *buf;            /* bytes from the server, starting at snd_una (+1 for SYN) */
    int buflen;
    int remote_eof;          /* server closed: send FIN after the data */
    int fin_sent;
    int console_fin;
    uint32_t last_progress_ms;
    /* diagnostics */
    uint32_t open_ms;
    uint32_t bytes_up;       /* console -> server, accepted by the socket */
    uint32_t bytes_down;     /* server -> console, read from the socket */
    uint32_t retransmits;
} tcp_conn;

static tcp_conn tcp_conns[MAX_TCP];

static void tcp_send(tcp_conn *c, uint32_t seq, uint8_t flags, const uint8_t *data, int len)
{
    uint8_t buf[14 + 20 + 24 + TCP_MSS];
    uint8_t *tcp = buf + 34;
    int hl = 20;

    wr16(tcp, c->rport);
    wr16(tcp + 2, c->cport);
    wr32(tcp + 4, seq);
    wr32(tcp + 8, c->rcv_nxt);
    if (flags & TH_SYN) {
        hl = 24;
        tcp[20] = 2;         /* MSS option */
        tcp[21] = 4;
        wr16(tcp + 22, TCP_MSS);
    }
    tcp[12] = (hl / 4) << 4;
    tcp[13] = flags;
    wr16(tcp + 14, 16384);   /* our window */
    wr16(tcp + 16, 0);
    wr16(tcp + 18, 0);
    if (len)
        memcpy(tcp + hl, data, len);
    wr16(tcp + 16, l4_csum(tcp, hl + len, 6, c->rip, IP_CLIENT));
    send_ip(buf, hl + len, 6, c->rip, IP_CLIENT);
}

static void tcp_free(tcp_conn *c, const char *why)
{
    if (log_level >= 1 && c->state != T_FREE)
        log_line("net: TCP %u.%u.%u.%u:%u closed (%s): %u bytes up, %u down, %u retransmits, %u ms",
                 c->rip >> 24, (c->rip >> 16) & 255, (c->rip >> 8) & 255, c->rip & 255, c->rport,
                 why, c->bytes_up, c->bytes_down, c->retransmits, now_ms - c->open_ms);
    if (c->fd > 0)
        close(c->fd);
    free(c->buf);
    memset(c, 0, sizeof(*c));
}

static void tcp_rst_reply(uint32_t src, uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack,
                          int had_ack)
{
    tcp_conn tmp;

    memset(&tmp, 0, sizeof(tmp));
    tmp.rip = src;
    tmp.rport = sport;
    tmp.cport = dport;
    tmp.rcv_nxt = ack;
    tcp_send(&tmp, had_ack ? seq : 0, TH_RST | TH_ACK, NULL, 0);
}

static tcp_conn *tcp_find(uint32_t rip, uint16_t rport, uint16_t cport)
{
    int i;

    for (i = 0; i < MAX_TCP; i++) {
        tcp_conn *c = &tcp_conns[i];
        if (c->state != T_FREE && c->rip == rip && c->rport == rport && c->cport == cport)
            return c;
    }
    return NULL;
}

static void tcp_open(uint32_t rip, uint16_t rport, uint16_t cport, uint32_t seq, uint16_t mss)
{
    struct sockaddr_in sa;
    tcp_conn *c = NULL;
    int i;

    for (i = 0; i < MAX_TCP; i++) {
        if (tcp_conns[i].state == T_FREE) {
            c = &tcp_conns[i];
            break;
        }
    }
    if (!c) {
        log_line("net: too many TCP connections");
        return;
    }

    c->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->fd < 0) {
        log_line("net: tcp socket: %s", strerror(errno));
        c->fd = 0;
        return;
    }
    set_nonblock(c->fd);
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(rip);
    sa.sin_port = htons(rport);
    if (connect(c->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 && errno != EINPROGRESS) {
        log_line("net: connect %u.%u.%u.%u:%u: %s", rip >> 24, (rip >> 16) & 255,
                 (rip >> 8) & 255, rip & 255, rport, strerror(errno));
        close(c->fd);
        c->fd = 0;
        return;
    }

    c->state = T_CONNECTING;
    c->rip = rip;
    c->rport = rport;
    c->cport = cport;
    c->rcv_nxt = seq + 1;
    c->iss = (uint32_t)rand() << 8;
    c->snd_una = c->iss;
    c->snd_nxt = c->iss;
    c->mss = mss && mss < TCP_MSS ? mss : TCP_MSS;
    c->cwnd = 2048;
    c->buf = malloc(TCP_BUF);
    c->last_progress_ms = now_ms;
    c->open_ms = now_ms;
    if (log_level >= 1)
        log_line("net: TCP connect %u.%u.%u.%u:%u", rip >> 24, (rip >> 16) & 255,
                 (rip >> 8) & 255, rip & 255, rport);
}

static void handle_tcp(const uint8_t *ip, int iplen, int ihl)
{
    const uint8_t *tcp = ip + ihl;
    uint32_t rip = rd32(ip + 16), seq, ack;
    uint16_t sport, dport;
    int hl, len;
    uint8_t flags;
    tcp_conn *c;

    if (iplen < ihl + 20)
        return;
    sport = rd16(tcp);
    dport = rd16(tcp + 2);
    seq = rd32(tcp + 4);
    ack = rd32(tcp + 8);
    hl = (tcp[12] >> 4) * 4;
    flags = tcp[13];
    if (hl < 20 || ihl + hl > iplen)
        return;
    len = iplen - ihl - hl;

    c = tcp_find(rip, dport, sport);

    if (flags & TH_RST) {
        if (c)
            tcp_free(c, "reset by console");
        return;
    }

    if (!c) {
        if ((flags & (TH_SYN | TH_ACK)) == TH_SYN) {
            uint16_t mss = 0;
            int i;

            for (i = 20; i + 3 < hl; ) {
                if (tcp[i] == 0)
                    break;
                if (tcp[i] == 1) {
                    i++;
                    continue;
                }
                if (tcp[i] == 2 && tcp[i + 1] == 4)
                    mss = rd16(tcp + i + 2);
                if (tcp[i + 1] < 2)
                    break;
                i += tcp[i + 1];
            }
            tcp_open(rip, dport, sport, seq, mss);
        } else {
            tcp_rst_reply(rip, dport, sport, ack, seq + len + ((flags & (TH_SYN | TH_FIN)) ? 1 : 0),
                          flags & TH_ACK);
        }
        return;
    }

    if (flags & TH_SYN)
        return;   /* retransmitted SYN while connecting */

    if (flags & TH_ACK) {
        c->cwnd = rd16(tcp + 14);
        if (c->state == T_SYNACK_SENT && ack == c->iss + 1) {
            c->state = T_OPEN;
            c->snd_una = ack;
            c->last_progress_ms = now_ms;
        } else if (c->state == T_OPEN && (int32_t)(ack - c->snd_una) > 0 &&
                   (int32_t)(ack - c->snd_max) <= 0) {
            uint32_t acked = ack - c->snd_una;

            if ((int)acked > c->buflen)
                acked = c->buflen;   /* the rest acknowledges our FIN */
            if ((int)acked > c->buflen)
                acked = c->buflen;
            memmove(c->buf, c->buf + acked, c->buflen - acked);
            c->buflen -= acked;
            c->snd_una = ack;
            if ((int32_t)(c->snd_nxt - ack) < 0)
                c->snd_nxt = ack;
            c->last_progress_ms = now_ms;
        }
    }

    if (c->state != T_OPEN)
        return;

    if (len > 0) {
        if (seq == c->rcv_nxt && !c->console_fin) {
            ssize_t n = send(c->fd, tcp + hl, len, MSG_NOSIGNAL);

            /* Only acknowledge what the socket took; the console resends the rest. */
            if (n > 0) {
                dump_bytes("up  ", c->bytes_up, tcp + hl, n);
                c->rcv_nxt += n;
                c->bytes_up += n;
            }
        }
        tcp_send(c, c->snd_nxt, TH_ACK, NULL, 0);
    }

    if ((flags & TH_FIN) && seq + len == c->rcv_nxt && !c->console_fin) {
        c->console_fin = 1;
        c->rcv_nxt++;
        shutdown(c->fd, SHUT_WR);
        tcp_send(c, c->snd_nxt, TH_ACK, NULL, 0);
    }

    if (c->console_fin && c->fin_sent && c->snd_una == c->snd_max)
        tcp_free(c, "closed normally");
}

static void poll_tcp_conn(tcp_conn *c)
{
    struct pollfd pfd;
    int inflight, room;

    pfd.fd = c->fd;
    pfd.events = c->state == T_CONNECTING ? POLLOUT : POLLIN;
    pfd.revents = 0;

    if (c->state == T_CONNECTING) {
        int err = 0;
        socklen_t el = sizeof(err);

        if (poll(&pfd, 1, 0) <= 0)
            return;
        getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &el);
        if (err) {
            if (log_level >= 1)
                log_line("net: TCP connect failed: %s", strerror(err));
            tcp_send(c, 0, TH_RST | TH_ACK, NULL, 0);
            tcp_free(c, "server unreachable");
            return;
        }
        c->state = T_SYNACK_SENT;
        tcp_send(c, c->iss, TH_SYN | TH_ACK, NULL, 0);
        c->snd_nxt = c->iss + 1;
        c->snd_max = c->snd_nxt;
        c->last_progress_ms = now_ms;
        return;
    }

    if (c->state == T_SYNACK_SENT) {
        if (now_ms - c->last_progress_ms > TCP_RTO_MS) {
            tcp_send(c, c->iss, TH_SYN | TH_ACK, NULL, 0);
            c->last_progress_ms = now_ms;
        }
        return;
    }

    /* Read from the server while there is buffer space. */
    if (!c->remote_eof && c->buflen < TCP_BUF && poll(&pfd, 1, 0) > 0) {
        ssize_t n = recv(c->fd, c->buf + c->buflen, TCP_BUF - c->buflen, 0);

        if (n > 0) {
            dump_bytes("down", c->bytes_down, c->buf + c->buflen, n);
            c->buflen += n;
            c->bytes_down += n;
        } else if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            c->remote_eof = 1;
            if (log_level >= 1)
                log_line("net: TCP server closed after %u bytes down (%s)", c->bytes_down,
                         n == 0 ? "EOF" : strerror(errno));
        }
    }

    /* Retransmit (go-back-N) when the console stops acknowledging. */
    if (c->snd_max != c->snd_una && now_ms - c->last_progress_ms > TCP_RTO_MS) {
        c->snd_nxt = c->snd_una;
        c->fin_sent = 0;
        c->retransmits++;
        c->last_progress_ms = now_ms;
    }

    inflight = c->snd_nxt - c->snd_una;
    room = (c->cwnd < 8192 ? c->cwnd : 8192) - inflight;
    while (room > 0 && inflight < c->buflen) {
        int seg = c->buflen - inflight;

        if (seg > c->mss)
            seg = c->mss;
        if (seg > room)
            break;
        tcp_send(c, c->snd_nxt, TH_ACK | TH_PSH, c->buf + inflight, seg);
        c->snd_nxt += seg;
        inflight += seg;
        room -= seg;
    }

    if (c->remote_eof && !c->fin_sent && inflight == c->buflen) {
        tcp_send(c, c->snd_nxt, TH_FIN | TH_ACK, NULL, 0);
        c->snd_nxt++;
        c->fin_sent = 1;
    }
    if ((int32_t)(c->snd_nxt - c->snd_max) > 0)
        c->snd_max = c->snd_nxt;

    /* Drop connections that have been dead for a long time. */
    if (now_ms - c->last_progress_ms > 120000) {
        tcp_send(c, c->snd_nxt, TH_RST | TH_ACK, NULL, 0);
        tcp_free(c, "idle timeout");
    }
}

/* ---- entry points ---- */

void net_init(const char *dns)
{
    struct in_addr a;

    if (!dns || !dns[0] || inet_pton(AF_INET, dns, &a) != 1)
        inet_pton(AF_INET, "95.217.77.181", &a);
    dns_server = a.s_addr;
    log_line("net: DNS server %s", inet_ntoa(a));
}

void net_reset(void)
{
    int i;

    for (i = 0; i < MAX_UDP; i++) {
        if (udp_flows[i].fd > 0)
            close(udp_flows[i].fd);
    }
    memset(udp_flows, 0, sizeof(udp_flows));
    for (i = 0; i < MAX_TCP; i++) {
        if (tcp_conns[i].state != T_FREE)
            tcp_free(&tcp_conns[i], "network reset");
    }
    have_client_mac = 0;
}

void net_input(const uint8_t *eth, int len)
{
    const uint8_t *ip;
    int ihl, iplen;

    if (len < 14)
        return;
    memcpy(client_mac, eth + 6, 6);
    have_client_mac = 1;

    if (rd16(eth + 12) == ETH_ARP) {
        handle_arp(eth, len);
        return;
    }
    if (rd16(eth + 12) != ETH_IP || len < 14 + 20)
        return;

    ip = eth + 14;
    ihl = (ip[0] & 0xF) * 4;
    iplen = rd16(ip + 2);
    if ((ip[0] >> 4) != 4 || ihl < 20 || iplen < ihl || 14 + iplen > len)
        return;
    if (rd16(ip + 6) & 0x3FFF)
        return;   /* fragments are not supported */

    switch (ip[9]) {
    case 17:
        handle_udp(ip, iplen, ihl);
        break;
    case 6:
        handle_tcp(ip, iplen, ihl);
        break;
    }
}

void net_poll(void)
{
    int i;

    now_ms++;
    poll_udp();
    for (i = 0; i < MAX_TCP; i++) {
        if (tcp_conns[i].state != T_FREE)
            poll_tcp_conn(&tcp_conns[i]);
    }
}
