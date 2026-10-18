# kpm_dbg

All-in-one KernelPatch Module (KPM) kernel debug toolkit for APatch / KernelPatch.

## Features

| Feature | Interface | Notes |
|---|---|---|
| Cross-process read | `ioctl(-1, cmd, &req)` | Page-table walk, works on non-debuggable apps |
| Cross-process write | `ioctl(-1, cmd+1, &req)` | Same channel, 4MB per call |
| Kernel symbol lookup | `ctl0 "sym <name>"` | `kallsyms_lookup_name` wrapper |
| Kernel function call | `ctl0 "call <sym> [a0..a7]"` | Up to 8 args, returns u64 |
| Kernel inline hook | `ctl0 "hook <sym>"` | Resolve + register target |
| Unhook | `ctl0 "unhook <sym>"` | |
| Hook list | `ctl0 "hooks"` | |
| Process info | `ctl0 "info <pid>"` | task / pgd |
| Key retrieval | `ctl0 "get_key"` | Returns `<key_hex>-<cmd_hex>` |

## RE integration

This module speaks the **KPM Memory IOCTL** protocol used by `zygisk-re-mcp`.
Select `KPM Memory IOCTL` as the memory backend in the RE panel.

Protocol details:

```
ioctl(-1, cmd,     &req)   -> read
ioctl(-1, cmd + 1, &req)   -> write
```

```c
struct kpm_dbg_req {   /* 32 bytes, must match kernel side */
    uint64_t key;      /* offset  0 */
    int32_t  pid;      /* offset  8 */
    int32_t  size;     /* offset 12 */
    uint64_t addr;     /* offset 16 */
    void    *buffer;   /* offset 24 */
};
```

`key` and `cmd` are randomly generated on each module load. Fetch them once:

```
kpatch <superkey> kpm ctl0 kpm_dbg "get_key"
```

## Build

Requires `aarch64-linux-gnu-gcc` and the KernelPatch source tree.

```bash
make TARGET_COMPILE=aarch64-linux-gnu- KP_DIR=/path/to/KernelPatch
```

Output: `kpm_dbg.kpm`

GitHub Actions builds it automatically — see `.github/workflows/build.yml`.

## Load

APatch does **not** implement KPM "install" (as of the docs). Two ways:

1. **Embed** — merge into `boot.img` during APatch patching (persistent)
2. **Load** — hand to kernel immediately (lost on reboot)

```bash
# load
kpatch <superkey> kpm load /path/to/kpm_dbg.kpm

# control
kpatch <superkey> kpm ctl0 kpm_dbg "get_key"
kpatch <superkey> kpm ctl0 kpm_dbg "info 1234"
kpatch <superkey> kpm ctl0 kpm_dbg "sym commit_creds"
kpatch <superkey> kpm ctl0 kpm_dbg "r 1234 7f0000000000 64"

# unload
kpatch <superkey> kpm unload kpm_dbg
```

## Requirements

- APatch / KernelPatch with KPM support
- `kptools` **0.11+** (older `d09` builds have no `kpm` subcommand)
- ARM64 (aarch64) only

## License

GPL v2
