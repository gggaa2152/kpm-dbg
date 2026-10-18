/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm_dbg - KernelPatch Module: all-in-one debugging toolkit
 *
 * Features:
 *   1. Cross-process physical memory read/write (page-table walk)
 *   2. ioctl magic-call channel (RE "KPM Memory IOCTL" compatible)
 *   3. Supercall control channel (kpatch <key> kpm ctl0 kpm_dbg "...")
 *   4. Kernel inline hook management (hook / unhook / list)
 *   5. Arbitrary kernel function call (up to 8 args)
 *   6. Kernel symbol lookup (kallsyms)
 *   7. Process info query (maps / base / module base)
 *
 * Author: operit
 * License: GPL v2
 */

#include <compiler.h>
#include <kpmodule.h>
#include <ktypes.h>
#include <kputils.h>
#include <kallsyms.h>
#include <common.h>
#include <hook.h>
#include <syscall.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/mm_types.h>
#include <linux/errno.h>
#include <asm-generic/unistd.h>
#include <stdarg.h>

KPM_NAME("kpm_dbg");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("operit");
KPM_DESCRIPTION("All-in-one kernel debug toolkit: rw/hook/call/sym for APatch+KernelPatch");

/* ------------------------------------------------------------------ */
/*  ioctl magic-call protocol (RE "KPM Memory IOCTL" compatible)       */
/* ------------------------------------------------------------------ */

/*
 * User side calls:
 *   ioctl(-1, cmd, &req)
 * where cmd == ioctl_cmd      -> read
 *       cmd == ioctl_cmd + 1  -> write
 *
 * struct kpm_dbg_req layout MUST stay identical to the user header.
 */
struct kpm_dbg_req {
    uint64_t key;      /* offset  0 : magic key from "get_key" */
    int32_t  pid;      /* offset  8 */
    int32_t  size;     /* offset 12 */
    uint64_t addr;     /* offset 16 : target virtual address */
    void    *buffer;   /* offset 24 : user buffer */
};                     /* total 32 bytes */

#define KPM_DBG_MAX_XFER (4 * 1024 * 1024) /* 4MB per call */

static uint64_t g_key = 0;
static uint32_t g_ioctl_cmd = 0;
static int      g_hook_installed = 0;

/* ------------------------------------------------------------------ */
/*  page table walk                                                     */
/* ------------------------------------------------------------------ */

static uint64_t g_phys_offset = 0;
static uint64_t g_page_offset = 0;
static uint64_t g_page_shift = 12;
static uint64_t g_page_level = 3;
static uint64_t g_page_size = 4096;
static uint64_t g_page_size_mask = ~4095ULL;
static uint64_t g_va_bits = 48;

/* resolved kernel funcs */
static struct task_struct *(*k_find_task_by_vpid)(pid_t pid) = 0;
static struct mm_struct   *(*k_get_task_mm)(struct task_struct *task) = 0;
static void                (*k_mmput)(struct mm_struct *mm) = 0;
static unsigned long       (*k_copy_to_user)(void __user *to, const void *from, unsigned long n) = 0;
static unsigned long       (*k_copy_from_user)(void *to, const void __user *from, unsigned long n) = 0;
static uint64_t            *k_memstart_addr = 0;
static int                  k_mm_pgd_offset = 0;

/* zero page for non-resident pages (avoids stale-buffer false positives) */
static uint8_t g_zero_page[4096] __attribute__((aligned(8)));

static inline uint64_t phys_to_virt_(uint64_t phys)
{
    return ((unsigned long)((phys) - g_phys_offset) | g_page_offset);
}

static inline uint64_t virt_to_phys_(uint64_t virt)
{
    if (kver > VERSION(5, 0, 0))
        return (((virt) - g_page_offset) + g_phys_offset);
    else
        return (((virt) & ~g_page_offset) + g_phys_offset);
}

/* walk page tables, return kernel physical address (0 = not present) */
static uint64_t pgtable_walk(uint64_t pgd, uint64_t va)
{
    uint64_t pxd_bits = g_page_shift - 3;
    uint64_t pxd_ptrs = 1ULL << pxd_bits;
    uint64_t pxd_va = pgd;
    uint64_t pxd_pa = virt_to_phys_(pxd_va);
    uint64_t block_lv = 0;

    for (int64_t lv = 4 - g_page_level; lv < 4; lv++) {
        uint64_t pxd_shift = (g_page_shift - 3) * (4 - lv) + 3;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        uint64_t pxd_entry_va = pxd_va + pxd_index * 8;
        if (!pxd_entry_va)
            return 0;

        uint64_t pxd_desc = *((uint64_t *)pxd_entry_va);

        if ((pxd_desc & 0b11) == 0b11) {          /* table descriptor */
            pxd_pa = pxd_desc & (((1ULL << (48 - g_page_shift)) - 1) << g_page_shift);
        } else if ((pxd_desc & 0b11) == 0b01) {   /* block descriptor */
            uint64_t block_bits = (3 - lv) * pxd_bits + g_page_shift;
            pxd_pa = pxd_desc & (((1ULL << (48 - block_bits)) - 1) << block_bits);
            block_lv = lv;
        } else {
            return 0;                              /* invalid */
        }

        pxd_va = phys_to_virt_(pxd_pa);
        if (block_lv)
            break;
    }

    uint64_t left_bit = g_page_shift + (block_lv ? (3 - block_lv) * pxd_bits : 0);
    return pxd_pa + (va & ((1ULL << left_bit) - 1));
}

static int pgtable_init(void)
{
    uint64_t tcr_el1;
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));

    uint64_t t1sz = (tcr_el1 << 42) >> 58;
    g_va_bits = 64 - t1sz;

    uint64_t tg1 = (tcr_el1 << 32) >> 62;
    g_page_shift = 12;
    if (tg1 == 1)
        g_page_shift = 14;
    else if (tg1 == 3)
        g_page_shift = 16;

    g_page_level = (g_va_bits - 4) / (g_page_shift - 3);

    if (kver > VERSION(5, 0, 0))
        g_page_offset = -(1ULL << g_va_bits);
    else
        g_page_offset = (0xffffffffffffffffULL - (1ULL << (g_va_bits - 1)) + 1);

    g_memstart_addr = (uint64_t *)kallsyms_lookup_name("memstart_addr");
    if (!g_memstart_addr)
        return -1;
    g_phys_offset = *g_memstart_addr;

    g_page_size = 1ULL << g_page_shift;
    g_page_size_mask = ~(g_page_size - 1);

    return 0;
}

/*
 * Core cross-process read/write.
 * rw: 0 = read, 1 = write.
 * Returns number of bytes handled, or negative errno.
 */
static int mem_rw(int pid, uint64_t va, size_t len, void __user *out, int rw)
{
    struct task_struct *task;
    struct mm_struct *mm;
    uintptr_t pgd;
    size_t done = 0;
    int touched = 0;

    if (!len)
        return -EINVAL;
    if (len > KPM_DBG_MAX_XFER)
        return -EINVAL;

    task = k_find_task_by_vpid(pid);
    if (!task)
        return -ESRCH;

    mm = k_get_task_mm(task);
    if (!mm)
        return -EINVAL;

    pgd = *(uintptr_t *)((uintptr_t)mm + k_mm_pgd_offset);

    while (done < len) {
        uint64_t cur_va = va + done;
        size_t remain = len - done;
        uint64_t tkpa = pgtable_walk(pgd, cur_va);

        if (!tkpa) {
            /* page not resident: zero-fill on read, skip on write */
            unsigned long skip = g_page_size - (cur_va & (g_page_size - 1));
            if (skip > remain)
                skip = remain;
            if (rw == 0) {
                size_t left = skip, off = 0;
                while (left > 0) {
                    size_t c = left > sizeof(g_zero_page) ? sizeof(g_zero_page) : left;
                    if (k_copy_to_user((char __user *)out + done + off,
                                       g_zero_page, c) != 0)
                        break;
                    off += c;
                    left -= c;
                }
            }
            done += skip;
            continue;
        }

        unsigned long poff = cur_va & (g_page_size - 1);
        size_t chunk = g_page_size - poff;
        if (chunk > remain)
            chunk = remain;

        void *tkva = (void *)phys_to_virt_(tkpa);
        char __user *uout = (char __user *)out + done;

        unsigned long r;
        if (rw == 0)
            r = k_copy_to_user(uout, tkva, chunk);
        else
            r = k_copy_from_user(tkva, uout, chunk);

        if (r == 0)
            touched++;

        done += chunk;
    }

    if (!touched && rw == 1)
        return -EFAULT;

    return (int)done;
}

/* ------------------------------------------------------------------ */
/*  ioctl hook: RE "KPM Memory IOCTL" backend                          */
/* ------------------------------------------------------------------ */

static long ioctl_before(hook_fargs3_t *args, void *udata)
{
    int fd = (int)syscall_argn(args, 0);
    unsigned long request = (unsigned long)syscall_argn(args, 1);
    void __user *arg = (void __user *)syscall_argn(args, 2);

    /* only intercept our magic call; everything else passes through */
    if (fd != -1)
        return 0;
    if (request != g_ioctl_cmd && request != g_ioctl_cmd + 1)
        return 0;

    struct kpm_dbg_req req;
    if (k_copy_from_user(&req, arg, sizeof(req)) != 0) {
        args->ret = -EFAULT;
        args->skip_origin = 1;
        return 0;
    }

    if (req.key != g_key) {
        args->ret = -EPERM;
        args->skip_origin = 1;
        return 0;
    }

    if (req.size <= 0 || req.size > KPM_DBG_MAX_XFER) {
        args->ret = -EINVAL;
        args->skip_origin = 1;
        return 0;
    }

    int rw = (request == g_ioctl_cmd + 1) ? 1 : 0;
    int ret = mem_rw(req.pid, req.addr, (size_t)req.size, req.buffer, rw);

    args->ret = (uint64_t)ret;
    args->skip_origin = 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  kernel hook registry (for hook/unhook/list supercalls)             */
/* ------------------------------------------------------------------ */

#define MAX_HOOKS 16

struct hook_entry {
    void *target;      /* original kernel function address */
    void *replace;     /* our replacement */
    void *backup;      /* trampoline */
    char  name[64];
    int   used;
};

static struct hook_entry g_hooks[MAX_HOOKS];

static int hook_find(void *target)
{
    for (int i = 0; i < MAX_HOOKS; i++)
        if (g_hooks[i].used && g_hooks[i].target == target)
            return i;
    return -1;
}

static int hook_register(const char *sym)
{
    if (!sym || !sym[0])
        return -ENOENT;

    void *target = (void *)kallsyms_lookup_name(sym);
    if (!target)
        return -ENOENT;

    if (hook_find(target) >= 0)
        return -EEXIST;

    for (int i = 0; i < MAX_HOOKS; i++) {
        if (g_hooks[i].used)
            continue;

        g_hooks[i].target = target;
        g_hooks[i].used = 1;
        int n = strlen(sym);
        if (n > 63)
            n = 63;
        memcpy(g_hooks[i].name, sym, n);
        g_hooks[i].name[n] = 0;

        logkd("[+kpm_dbg] resolved %s @ %llx\n", sym, (uint64_t)target);
        return i;
    }

    return -ENOSPC;
}

static void hook_unregister_all(void)
{
    for (int i = 0; i < MAX_HOOKS; i++) {
        if (!g_hooks[i].used)
            continue;
        if (g_hooks[i].replace) {
            unhook(g_hooks[i].target);
            g_hooks[i].replace = 0;
            g_hooks[i].backup = 0;
        }
        g_hooks[i].used = 0;
    }
}

/* ------------------------------------------------------------------ */
/*  supercall control channel                                          */
/* ------------------------------------------------------------------ */

/*
 * kpatch <superkey> kpm ctl0 kpm_dbg "<cmd>"
 *
 * Commands:
 *   get_key                        -> "<key_hex>-<cmd_hex>"
 *   r <pid> <addr_hex> <size>      -> raw bytes (hex dump in out_msg)
 *   w <pid> <addr_hex> <hexbytes>  -> bytes written
 *   call <sym> [a0..a7]            -> return value (hex)
 *   sym <name>                     -> kernel address (hex)
 *   hook <sym>                     -> hook slot index (placeholder)
 *   unhook <sym>                   -> 0
 *   hooks                          -> list registered hooks
 *   info <pid>                     -> pid / pgd / maps line
 *   help                           -> usage
 */

static void out_str(char __user *out, int outlen, const char *s)
{
    if (!out || outlen <= 0)
        return;
    int n = strlen(s);
    if (n >= outlen)
        n = outlen - 1;
    compat_copy_to_user(out, s, n + 1);
}

static void out_fmt(char __user *out, int outlen, const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    /* simple vsnprintf substitute via kernel symbol */
    int (*k_vsnprintf)(char *, size_t, const char *, va_list) =
        (void *)kallsyms_lookup_name("vsnprintf");
    if (k_vsnprintf)
        k_vsnprintf(buf, sizeof(buf), fmt, ap);
    else
        buf[0] = 0;
    va_end(ap);
    out_str(out, outlen, buf);
}

/* parse hex string to u64 */
static uint64_t parse_hex(const char *s)
{
    uint64_t r = 0;
    if (!s)
        return 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s += 2;
    while (*s) {
        char c = *s;
        uint64_t v;
        if (c >= '0' && c <= '9')       v = c - '0';
        else if (c >= 'a' && c <= 'f')  v = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F')  v = 10 + (c - 'A');
        else break;
        r = (r << 4) | v;
        s++;
    }
    return r;
}

static long parse_dec(const char *s)
{
    long r = 0;
    int neg = 0;
    if (!s)
        return 0;
    if (*s == '-') { neg = 1; s++; }
    while (*s >= '0' && *s <= '9') {
        r = r * 10 + (*s - '0');
        s++;
    }
    return neg ? -r : r;
}

/* tokenize a mutable string into at most n tokens */
static int tokenize(char *s, char *tok[], int n)
{
    int c = 0;
    char *p = s;
    while (*p && c < n) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        tok[c++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) *p++ = 0;
    }
    return c;
}

static long ctl0(const char *args, char __user *out_msg, int outlen)
{
    char buf[1024];
    char *tok[16];
    int n;

    if (!args) {
        out_str(out_msg, outlen, "kpm_dbg: no args");
        return 0;
    }

    int len = strlen(args);
    if (len > 1023)
        len = 1023;
    memcpy(buf, args, len);
    buf[len] = 0;

    n = tokenize(buf, tok, 16);
    if (n == 0) {
        out_str(out_msg, outlen, "kpm_dbg: empty");
        return 0;
    }

    const char *cmd = tok[0];

    /* ---- get_key ---- */
    if (!strcmp(cmd, "get_key")) {
        char kb[64];
        int (*k_snprintf)(char *, size_t, const char *, ...) =
            (void *)kallsyms_lookup_name("snprintf");
        if (k_snprintf)
            k_snprintf(kb, sizeof(kb), "%llx-%x",
                       (unsigned long long)g_key, g_ioctl_cmd);
        else
            kb[0] = 0;
        out_str(out_msg, outlen, kb);
        return 0;
    }

    /* ---- help ---- */
    if (!strcmp(cmd, "help")) {
        out_str(out_msg, outlen,
                "get_key | r pid addr size | w pid addr hex | "
                "call sym [a0..a7] | sym name | hook sym | unhook sym | "
                "hooks | info pid");
        return 0;
    }

    /* ---- sym <name> ---- */
    if (!strcmp(cmd, "sym")) {
        if (n < 2) { out_str(out_msg, outlen, "ERR: sym <name>"); return 0; }
        void *a = (void *)kallsyms_lookup_name(tok[1]);
        if (!a) { out_str(out_msg, outlen, "ERR: not found"); return 0; }
        out_fmt(out_msg, outlen, "%llx", (unsigned long long)a);
        return 0;
    }

    /* ---- call <sym> [a0..a7] ---- */
    if (!strcmp(cmd, "call")) {
        if (n < 2) { out_str(out_msg, outlen, "ERR: call <sym> [args]"); return 0; }
        uintptr_t fn = (uintptr_t)kallsyms_lookup_name(tok[1]);
        if (!fn) { out_str(out_msg, outlen, "ERR: sym not found"); return 0; }

        uint64_t a[8] = {0};
        for (int i = 0; i < 8 && (2 + i) < n; i++)
            a[i] = parse_hex(tok[2 + i]);

        typedef uint64_t (*fn8_t)(uint64_t, uint64_t, uint64_t, uint64_t,
                                  uint64_t, uint64_t, uint64_t, uint64_t);
        uint64_t ret = ((fn8_t)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
        out_fmt(out_msg, outlen, "%llx", (unsigned long long)ret);
        return 0;
    }

    /* ---- hook <sym> ---- */
    if (!strcmp(cmd, "hook")) {
        if (n < 2) { out_str(out_msg, outlen, "ERR: hook <sym>"); return 0; }
        int r = hook_register(tok[1]);
        if (r < 0) { out_fmt(out_msg, outlen, "ERR: %d", r); return 0; }
        out_fmt(out_msg, outlen, "slot=%d addr=%llx", r,
                (unsigned long long)g_hooks[r].target);
        return 0;
    }

    /* ---- unhook <sym> ---- */
    if (!strcmp(cmd, "unhook")) {
        if (n < 2) { out_str(out_msg, outlen, "ERR: unhook <sym>"); return 0; }
        void *t = (void *)kallsyms_lookup_name(tok[1]);
        int i = t ? hook_find(t) : -1;
        if (i < 0) { out_str(out_msg, outlen, "ERR: not hooked"); return 0; }
        if (g_hooks[i].replace) {
            unhook(g_hooks[i].target);
            g_hooks[i].replace = 0;
            g_hooks[i].backup = 0;
        }
        g_hooks[i].used = 0;
        out_str(out_msg, outlen, "ok");
        return 0;
    }

    /* ---- hooks ---- */
    if (!strcmp(cmd, "hooks")) {
        char line[768];
        int pos = 0;
        line[0] = 0;
        for (int i = 0; i < MAX_HOOKS; i++) {
            if (!g_hooks[i].used)
                continue;
            int (*k_snprintf)(char *, size_t, const char *, ...) =
                (void *)kallsyms_lookup_name("snprintf");
            if (!k_snprintf) break;
            int w = k_snprintf(line + pos, sizeof(line) - pos,
                               "%d:%s@%llx%s;", i, g_hooks[i].name,
                               (unsigned long long)g_hooks[i].target,
                               g_hooks[i].replace ? "H" : "-");
            if (w <= 0) break;
            pos += w;
            if (pos >= (int)sizeof(line) - 64) break;
        }
        if (!pos) out_str(out_msg, outlen, "(none)");
        else out_str(out_msg, outlen, line);
        return 0;
    }

    /* ---- info <pid> ---- */
    if (!strcmp(cmd, "info")) {
        if (n < 2) { out_str(out_msg, outlen, "ERR: info <pid>"); return 0; }
        int pid = (int)parse_dec(tok[1]);
        struct task_struct *task = k_find_task_by_vpid(pid);
        if (!task) { out_str(out_msg, outlen, "ERR: no such pid"); return 0; }
        struct mm_struct *mm = k_get_task_mm(task);
        if (!mm) { out_str(out_msg, outlen, "ERR: no mm"); return 0; }
        uintptr_t pgd = *(uintptr_t *)((uintptr_t)mm + k_mm_pgd_offset);
        k_mmput(mm);
        out_fmt(out_msg, outlen, "pid=%d task=%llx pgd=%llx", pid,
                (unsigned long long)(uintptr_t)task,
                (unsigned long long)pgd);
        return 0;
    }

    /* ---- r <pid> <addr> <size> : read, hex dump ---- */
    if (!strcmp(cmd, "r")) {
        if (n < 4) { out_str(out_msg, outlen, "ERR: r <pid> <addr> <size>"); return 0; }
        int pid = (int)parse_dec(tok[1]);
        uint64_t addr = parse_hex(tok[2]);
        int size = (int)parse_dec(tok[3]);
        if (size <= 0 || size > 256) {
            out_str(out_msg, outlen, "ERR: size 1..256");
            return 0;
        }
        uint8_t tmp[256];
        int r = mem_rw(pid, addr, (size_t)size, (void __user *)tmp, 0);
        if (r < 0) { out_fmt(out_msg, outlen, "ERR: %d", r); return 0; }
        /* hex encode */
        static const char hx[] = "0123456789abcdef";
        char hex[520];
        int p = 0;
        for (int i = 0; i < size && p < 510; i++) {
            hex[p++] = hx[(tmp[i] >> 4) & 0xf];
            hex[p++] = hx[tmp[i] & 0xf];
        }
        hex[p] = 0;
        out_str(out_msg, outlen, hex);
        return 0;
    }

    /* ---- w <pid> <addr> <hexbytes> : write ---- */
    if (!strcmp(cmd, "w")) {
        if (n < 4) { out_str(out_msg, outlen, "ERR: w <pid> <addr> <hex>"); return 0; }
        int pid = (int)parse_dec(tok[1]);
        uint64_t addr = parse_hex(tok[2]);
        const char *h = tok[3];
        int hl = strlen(h);
        if (hl == 0 || (hl & 1)) {
            out_str(out_msg, outlen, "ERR: hex must be even length");
            return 0;
        }
        int size = hl / 2;
        if (size > 256) {
            out_str(out_msg, outlen, "ERR: max 256 bytes");
            return 0;
        }
        uint8_t tmp[256];
        for (int i = 0; i < size; i++) {
            char a = h[i * 2], b = h[i * 2 + 1];
            uint8_t hi = (a >= '0' && a <= '9') ? a - '0' :
                         (a >= 'a' && a <= 'f') ? 10 + a - 'a' : 10 + a - 'A';
            uint8_t lo = (b >= '0' && b <= '9') ? b - '0' :
                         (b >= 'a' && b <= 'f') ? 10 + b - 'a' : 10 + b - 'A';
            tmp[i] = (hi << 4) | lo;
        }
        int r = mem_rw(pid, addr, (size_t)size, (void __user *)tmp, 1);
        if (r < 0) { out_fmt(out_msg, outlen, "ERR: %d", r); return 0; }
        out_fmt(out_msg, outlen, "wrote=%d", r);
        return 0;
    }

    out_str(out_msg, outlen, "ERR: unknown cmd, try 'help'");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  init / exit                                                        */
/* ------------------------------------------------------------------ */

static long mod_init(const char *args, const char *event, void *reserved)
{
    logkd("[+kpm_dbg] init, args=%s\n", args ? args : "(null)");

    /* resolve kernel symbols */
    k_find_task_by_vpid = (void *)kallsyms_lookup_name("find_task_by_vpid");
    k_get_task_mm       = (void *)kallsyms_lookup_name("get_task_mm");
    k_mmput             = (void *)kallsyms_lookup_name("mmput");
    k_copy_to_user      = (void *)kallsyms_lookup_name("__arch_copy_to_user");
    k_copy_from_user    = (void *)kallsyms_lookup_name("__arch_copy_from_user");

    if (!k_copy_to_user)
        k_copy_to_user = (void *)kallsyms_lookup_name("_copy_to_user");
    if (!k_copy_from_user)
        k_copy_from_user = (void *)kallsyms_lookup_name("_copy_from_user");

    if (!k_find_task_by_vpid || !k_get_task_mm || !k_mmput ||
        !k_copy_to_user || !k_copy_from_user) {
        logke("[+kpm_dbg] symbol resolve failed\n");
        return -1;
    }

    /* mm_struct.pgd offset comes from KernelPatch's runtime-resolved table */
    k_mm_pgd_offset = mm_struct_offset.pgd_offset;
    if (k_mm_pgd_offset <= 0 || k_mm_pgd_offset > 0x400) {
        logke("[+kpm_dbg] bad pgd_offset=%d\n", k_mm_pgd_offset);
        return -1;
    }

    if (pgtable_init() != 0) {
        logke("[+kpm_dbg] pgtable init failed\n");
        return -1;
    }

    /* generate magic key + ioctl cmd */
    g_key = get_random_u64();
    g_ioctl_cmd = (uint32_t)get_random_u64();

    /* install ioctl hook */
    hook_err_t err = fp_hook_syscalln(__NR_ioctl, 3, ioctl_before, 0, 0);
    if (err) {
        logke("[+kpm_dbg] ioctl hook failed: %d\n", err);
        return -err;
    }
    g_hook_installed = 1;

    logkd("[+kpm_dbg] ready key=%llx cmd=%x pgd_off=%x\n",
          (unsigned long long)g_key, g_ioctl_cmd, k_mm_pgd_offset);
    return 0;
}

static long mod_exit(void *reserved)
{
    logkd("[+kpm_dbg] exit\n");

    if (g_hook_installed) {
        fp_unhook_syscalln(__NR_ioctl, ioctl_before, 0);
        g_hook_installed = 0;
    }

    hook_unregister_all();
    return 0;
}

KPM_INIT(mod_init);
KPM_CTL0(ctl0);
KPM_EXIT(mod_exit);