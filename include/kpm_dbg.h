/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm_dbg user-space API header
 *
 * Kernel side: src/kpm_dbg.c  (struct kpm_dbg_req must stay in sync)
 */

#ifndef _KPM_DBG_UAPI_H_
#define _KPM_DBG_UAPI_H_

#include <stdint.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Request descriptor passed to ioctl(-1, cmd, &req).
 * Layout MUST match the kernel-side struct exactly (32 bytes). */
struct kpm_dbg_req {
    uint64_t key;      /* magic key obtained from "get_key" supercall */
    int32_t  pid;      /* target process pid */
    int32_t  size;     /* bytes to transfer (1 .. 4MB) */
    uint64_t addr;     /* target virtual address in the target process */
    void    *buffer;   /* user-space buffer (source for write, dest for read) */
};

/*
 * The two magic ioctl request values are:
 *     cmd        -> read
 *     cmd + 1    -> write
 * They are randomly generated per module load and must be fetched once via
 *   kpatch <superkey> kpm ctl0 kpm_dbg "get_key"
 * which returns "<key_hex>-<cmd_hex>".
 */

struct kpm_dbg_handle {
    uint64_t key;
    uint32_t cmd;
    int      ready;
};

/* Parse "key-cmd" (both hex) as returned by the get_key supercall. */
static inline int kpm_dbg_parse_key(const char *s, struct kpm_dbg_handle *h)
{
    if (!s || !h) return -1;
    uint64_t k = 0;
    uint32_t c = 0;
    const char *p = s;

    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    while (*p && *p != '-') {
        char ch = *p;
        uint64_t v;
        if (ch >= '0' && ch <= '9')      v = ch - '0';
        else if (ch >= 'a' && ch <= 'f') v = 10 + ch - 'a';
        else if (ch >= 'A' && ch <= 'F') v = 10 + ch - 'A';
        else return -1;
        k = (k << 4) | v;
        p++;
    }
    if (*p != '-') return -1;
    p++;

    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    while (*p) {
        char ch = *p;
        uint32_t v;
        if (ch >= '0' && ch <= '9')      v = ch - '0';
        else if (ch >= 'a' && ch <= 'f') v = 10 + ch - 'a';
        else if (ch >= 'A' && ch <= 'F') v = 10 + ch - 'A';
        else return -1;
        c = (c << 4) | v;
        p++;
    }

    h->key = k;
    h->cmd = c;
    h->ready = 1;
    return 0;
}

/* Read memory from target process. Returns bytes read or negative errno. */
static inline long kpm_dbg_read(const struct kpm_dbg_handle *h,
                                int pid, uint64_t addr,
                                void *buf, int size)
{
    if (!h || !h->ready) return -EINVAL;
    struct kpm_dbg_req req;
    req.key = h->key;
    req.pid = pid;
    req.size = size;
    req.addr = addr;
    req.buffer = buf;
    return ioctl(-1, h->cmd, &req);
}

/* Write memory into target process. Returns bytes written or negative errno. */
static inline long kpm_dbg_write(const struct kpm_dbg_handle *h,
                                 int pid, uint64_t addr,
                                 const void *buf, int size)
{
    if (!h || !h->ready) return -EINVAL;
    struct kpm_dbg_req req;
    req.key = h->key;
    req.pid = pid;
    req.size = size;
    req.addr = addr;
    req.buffer = (void *)buf;
    return ioctl(-1, h->cmd + 1, &req);
}

#ifdef __cplusplus
}
#endif

#endif /* _KPM_DBG_UAPI_H_ */
