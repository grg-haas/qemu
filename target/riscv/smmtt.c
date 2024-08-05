
#include "smmtt.h"

#include "qemu/log.h"
#include "qapi/error.h"
#include "trace.h"
#include "exec/exec-all.h"

/*
 * Definitions
 */

static const unsigned long long masks_rw[] = {
        MTTL1_RW, MTTL2_RW, MTTL3
};

static const unsigned long long masks[] = {
        MTTL1, MTTL2, MTTL3,
};

#define MTTL2_FIELD_GET(entry, rw, field) \
    ((rw) ? (entry.mttl2.mttl2_rw.field) : (entry.mttl2.mttl2.field))

#define MTTL2_TYPE(rw, type) \
    ((rw) ? (SMMTT_TYPE_RW_##type) : (SMMTT_TYPE_##type))

#define IS_MTTL2_1G_TYPE(rw, type) \
    ((rw) ? (type == SMMTT_TYPE_RW_1G_DISALLOW || \
                type == SMMTT_TYPE_RW_1G_ALLOW_R || \
                type == SMMTT_TYPE_RW_1G_ALLOW_RW) : \
    (type == SMMTT_TYPE_1G_DISALLOW || type == SMMTT_TYPE_1G_ALLOW))

/*
 * Internal helpers
 */

static int smmtt_decode_mttp(CPURISCVState *env, bool *rw, int *levels) {
    smmtt_mode_t smmtt_mode = get_field(env->mttp, MTTP_MODE);

    switch (smmtt_mode) {
        case SMMTT_BARE:
            *levels = -1;
            break;

            // Determine if rw
#if defined(TARGET_RISCV32)
            case SMMTT_34_rw:
#elif defined(TARGET_RISCV64)
        case SMMTT_46_rw:
#endif
            *rw = true;
#if defined(TARGET_RISCV32)
            // fall through
            case SMMTT_34:
#elif defined(TARGET_RISCV64)
            // fall through
        case SMMTT_46:
#endif
            *levels = 2;
            break;

            // Handle 56 bit lookups (3 stage)
#if defined(TARGET_RISCV64)
        case SMMTT_56_rw:
            *rw = true;
            // fall through
        case SMMTT_56:
            *levels = 3;
            break;
#endif
        default:
            return -1;
    }

    return 0;
}

static int mttl1_privs_from_perms(uint64_t perms, bool rw, int *privs) {
    if (rw) {
        switch ((smmtt_perms_mtt_l1_dir_rw_t) perms) {
            case SMMTT_PERMS_MTT_L1_DIR_RW_DISALLOWED:
                *privs = 0;
                break;

            case SMMTT_PERMS_MTT_L1_DIR_RW_READ_WRITE:
                *privs |= (PROT_WRITE);
                // fall through
            case SMMTT_PERMS_MTT_L1_DIR_RW_READ:
                *privs |= (PROT_READ);
                break;

            default:
                return -1;
        }
    } else {
        switch ((smmtt_perms_mtt_l1_dir_t) perms) {
            case SMMTT_PERMS_MTT_L1_DIR_DISALLOWED:
                *privs = 0;
                break;

            case SMMTT_PERMS_MTT_L1_DIR_ALLOWED:
                *privs = (PROT_READ | PROT_WRITE | PROT_EXEC);
                break;

            default:
                return -1;
        }
    }

    return 0;
}

static int smmtt_decode_mttl1(hwaddr addr, bool rw, smmtt_mtt_entry_t entry, int *privs) {
    target_ulong offset = get_field(addr, rw ? MTTL1_RW_OFFS : MTTL1_OFFS);
    uint64_t field = MTT_PERM_FIELD(1, rw, L1_DIR, offset);
    uint64_t perms = get_field(entry.mttl1, field);

    return mttl1_privs_from_perms(perms, rw, privs);
}

static int mttl2_2m_privs_from_perms(uint64_t perms, bool rw, int *privs) {
    if (rw) {
        switch ((smmtt_perms_2m_pages_rw_t) perms) {
            case SMMTT_PERMS_2M_PAGES_RW_DISALLOWED:
                *privs = 0;
                break;

            case SMMTT_PERMS_2M_PAGES_RW_READ_WRITE:
                *privs |= PAGE_WRITE;
                // fall through
            case SMMTT_PERMS_2M_PAGES_RW_READ:
                *privs |= PAGE_READ;
                break;

            default:
                return -1;
        }
    } else {
        switch ((smmtt_perms_2m_pages_t) perms) {
            case SMMTT_PERMS_2M_PAGES_DISALLOWED:
                *privs = 0;
                break;

            case SMMTT_PERMS_2M_PAGES_ALLOWED:
                *privs = (PAGE_READ | PAGE_WRITE | PAGE_EXEC);
                break;

            default:
                return -1;
        }
    }

    return 0;
}

static int smmtt_decode_mttl2_2m_pages(hwaddr addr, bool rw, smmtt_mtt_entry_t entry,
                                       int *privs) {
    target_ulong idx;
    uint64_t perms;
    uint32_t field;

    if (MTTL2_FIELD_GET(entry, rw, info) >> 32 != 0) {
        return -1;
    }

    idx = get_field(addr, rw ? MTTL2_RW_OFFS : MTTL2_OFFS);
    field = MTT_PERM_FIELD(2, rw, 2M_PAGES, idx);
    perms = get_field(MTTL2_FIELD_GET(entry, rw, info), field);

    return mttl2_2m_privs_from_perms(perms, rw, privs);;
}

static int mttl2_1g_privs_from_type(uint64_t type, bool rw, int *privs) {
    if (rw) {
        switch ((smmtt_type_rw_t) type) {
            case SMMTT_TYPE_RW_1G_DISALLOW:
                *privs = 0;
                break;

            case SMMTT_TYPE_RW_1G_ALLOW_RW:
                *privs |= PAGE_WRITE;
                // fall through
            case SMMTT_TYPE_RW_1G_ALLOW_R:
                *privs |= PAGE_READ;
                break;

            default:
                return -1;
        }
    } else {
        switch ((smmtt_type_t) type) {
            case SMMTT_TYPE_1G_DISALLOW:
                *privs = 0;
                break;
            case SMMTT_TYPE_1G_ALLOW:
                *privs = (PAGE_READ | PAGE_WRITE | PAGE_EXEC);
                break;

            default:
                return -1;
        }
    }

    return 0;
}

static int smmtt_decode_mttl2(hwaddr addr, bool rw, smmtt_mtt_entry_t entry,
                              int *privs, hwaddr *next, bool *done) {
    int ret = 0;
    uint64_t type;
    *done = false;

    if (MTTL2_FIELD_GET(entry, rw, zero) != 0) {
        *done = true;
        return -1;
    }

    type = MTTL2_FIELD_GET(entry, rw, type);

    if (type == MTTL2_TYPE(rw, MTT_L1_DIR)) {
        *next = MTTL2_FIELD_GET(entry, rw, info) << PGSHIFT;
        *done = false;
    } else if (type == MTTL2_TYPE(rw, 2M_PAGES)) {
        ret = smmtt_decode_mttl2_2m_pages(addr, rw, entry, privs);
        *done = true;
    } else if (IS_MTTL2_1G_TYPE(rw, type)) {
        ret = mttl2_1g_privs_from_type(type, rw, privs);
        *done = true;
    } else {
        return -1;
    }

    return ret;
}

static int smmtt_decode_mttl3(smmtt_mtt_entry_t entry, hwaddr *next, bool *done) {
    if (entry.mttl3.zero != 0) {
        return -1;
    }

    *next = entry.mttl3.mttl2_ppn << PGSHIFT;
    *done = false;
    return 0;
}

/*
 * Public Interface
 */


bool smmtt_hart_has_privs(CPURISCVState *env, hwaddr addr,
                          target_ulong size, int privs,
                          int *allowed_privs, target_ulong mode) {
    // SMMTT configuration
    bool rw = false;
    int levels = 0;
    smmtt_mtt_entry_t entry = {
            .raw = 0,
    };

    const unsigned long long *msk;

    // Results and indices
    bool done = false;
    int ret;
    MemTxResult res;
    target_ulong idx;
    hwaddr curr;

    CPUState *cs = env_cpu(env);
    if (!riscv_cpu_cfg(env)->ext_smmtt || (mode == PRV_M)) {
        *allowed_privs = (PAGE_READ | PAGE_WRITE | PAGE_EXEC);
        return true;
    }

    ret = smmtt_decode_mttp(env, &rw, &levels);
    if (ret < 0) {
        return false;
    }

    if (levels == -1) {
        // This must be SMMTT_BARE, so SMMTT will allow accesses here
        *allowed_privs = (PAGE_READ | PAGE_WRITE | PAGE_EXEC);
    } else {
        // Initialize allowed privileges to 0 and discover
        // what's allowed on the way.
        *allowed_privs = 0;
    }

    msk = rw ? masks_rw : masks;
    curr = (hwaddr) get_field(env->mttp, MTTP_PPN) << PGSHIFT;

    for (; levels > 0 && !done; levels--) {
        idx = get_field(addr, msk[levels - 1]);
        curr = curr + idx * 8;
        entry.raw = address_space_ldq(cs->as, curr, MEMTXATTRS_UNSPECIFIED, &res);

        switch (levels) {
            case 3:
                ret = smmtt_decode_mttl3(entry, &curr, &done);
                if (ret < 0) {
                    return false;
                }
                break;

            case 2:
                ret = smmtt_decode_mttl2(addr, rw, entry, allowed_privs,
                                         &curr, &done);
                if (ret < 0) {
                    return false;
                }
                break;

            case 1:
                ret = smmtt_decode_mttl1(addr, rw, entry, allowed_privs);
                if (ret < 0) {
                    return false;
                }
                break;

            default:
                return false;

        }
    }

    // ASSUMPTION: we assume that read implies execute, and leave it up to other
    // parts of the memory hierarchy to indicate execute permissions.
    if (*allowed_privs & PROT_READ) {
        *allowed_privs |= PROT_EXEC;
    }

    return (privs & *allowed_privs) == privs;
}
