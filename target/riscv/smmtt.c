
#include "smmtt.h"

#include "qemu/log.h"
#include "qapi/error.h"
#include "trace.h"
#include "exec/exec-all.h"

/*
 * Definitions
 */

static const unsigned long long masks[] = {
        SPA_PN0, SPA_PN1, SPA_PN2,
#if defined(TARGET_RISCV64)
        SPA_PN3
#endif
};

#define MTTL2_FIELD_GET(entry, field) ((entry)->field)

#define MTTL2_TYPE(type) \
    (SMMTT_TYPE_##type)

#define IS_MTTL2_1G_TYPE(type) \
    ((type) == SMMTT_TYPE_1G_DISALLOW || \
     (type) == SMMTT_TYPE_1G_ALLOW_RX || \
     (type) == SMMTT_TYPE_1G_ALLOW_RW || \
     (type) == SMMTT_TYPE_1G_ALLOW_RWX)

/*
 * Internal helpers
 */

static int smmtt_decode_mttp(CPURISCVState *env, int *levels) {
    smmtt_mode_t smmtt_mode = get_field(env->mttp, MTTP_MODE);

    switch (smmtt_mode) {
        case SMMTT_BARE:
            *levels = -1;
            break;

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
        case SMMTT_56:
            *levels = 3;
            break;
#endif
        default:
            return -1;
    }

    return 0;
}

static int mttl1_privs_from_perms(uint64_t perms, int *privs) {
    switch((smmtt_perms_mtt_l1_dir_t) perms) {
        case SMMTT_PERMS_MTT_L1_DIR_DISALLOWED:
            *privs = 0;
            break;

        case SMMTT_PERMS_MTT_L1_DIR_ALLOW_RX:
            *privs |= (PROT_READ | PROT_EXEC);
            break;

        case SMMTT_PERMS_MTT_L1_DIR_ALLOW_RW:
            *privs |= (PROT_READ | PROT_WRITE);
            break;

        case SMMTT_PERMS_MTT_L1_DIR_ALLOW_RWX:
            *privs |= (PROT_READ | PROT_WRITE | PROT_EXEC);
    }

    return 0;
}

static int smmtt_decode_mttl1(hwaddr addr, mttl1_entry_t entry, int *privs) {
    target_ulong offset = get_field(addr, SPA_PN0);
    uint64_t field = MTT_PERM_FIELD(offset);
    uint64_t perms = get_field(entry, field);

    return mttl1_privs_from_perms(perms, privs);
}

static int mttl2_xm_privs_from_perms(uint64_t perms, int *privs) {
    switch((smmtt_perms_xm_pages_t) perms) {
        case SMMTT_PERMS_XM_PAGES_DISALLOWED:
            *privs = 0;
            break;

        case SMMTT_PERMS_XM_PAGES_ALLOW_RX:
            *privs |= (PROT_READ | PROT_EXEC);
            break;

        case SMMTT_PERMS_XM_PAGES_ALLOW_RW:
            *privs |= (PROT_READ | PROT_WRITE);
            break;

        case SMMTT_PERMS_XM_PAGES_ALLOW_RWX:
            *privs |= (PROT_READ | PROT_WRITE | PROT_EXEC);
    }

    return 0;
}

static int smmtt_decode_mttl2_xm_pages(hwaddr addr, mttl2_entry_t entry,
                                       int *privs) {
    target_ulong idx;
    uint64_t perms;
    uint32_t field;

#if defined(TARGET_RISCV32)
    if (entry.info >> 16 != 0) {
        return -1;
    }
#else
    if (entry.info >> 32 != 0) {
        return -1;
    }
#endif

    idx = get_field(addr, SPA_XM_OFFS);
    field = MTT_PERM_FIELD( idx);
    perms = get_field(entry.info, field);

    return mttl2_xm_privs_from_perms(perms, privs);;
}

static int mttl2_1g_privs_from_type(uint64_t type, int *privs) {
    switch((smmtt_type_t) type) {
        case SMMTT_TYPE_1G_DISALLOW:
            *privs = 0;
            break;

        case SMMTT_TYPE_1G_ALLOW_RX:
            *privs |= (PROT_READ | PROT_EXEC);
            break;

        case SMMTT_TYPE_1G_ALLOW_RW:
            *privs |= (PROT_READ | PROT_WRITE);
            break;

        case SMMTT_TYPE_1G_ALLOW_RWX:
            *privs |= (PROT_READ | PROT_WRITE | PROT_EXEC);
            break;

        default:
            *privs = 0;
            return -1;
    }

    return 0;
}

static int smmtt_decode_mttl2(hwaddr addr, mttl2_entry_t entry,
                              int *privs, hwaddr *next, bool *done) {
    int ret = 0;
    uint64_t type;
    *done = false;

    if (entry.zero != 0) {
        *done = true;
        return -1;
    }

    type = entry.type;

    if (type == SMMTT_TYPE_MTT_L1_DIR) {
        *next = (hwaddr) entry.info << PGSHIFT;
        *done = false;
    } else
#if defined(TARGET_RISCV32)
        if (type == SMMTT_TYPE_4M_PAGES) {
#else
        if (type == SMMTT_TYPE_2M_PAGES) {
#endif
        ret = smmtt_decode_mttl2_xm_pages(addr, entry, privs);
        *done = true;
    } else if (IS_MTTL2_1G_TYPE(type)) {
        ret = mttl2_1g_privs_from_type(type, privs);
        *done = true;
    } else {
        return -1;
    }

    return ret;
}

#if defined(TARGET_RISCV64)
static int smmtt_decode_mttl3(mttl3_entry_t entry, hwaddr *next, bool *done) {
    if (entry.zero != 0) {
        return -1;
    }

    *next = entry.mttl2_ppn << PGSHIFT;
    *done = false;
    return 0;
}
#endif

/*
 * Public Interface
 */


bool smmtt_hart_has_privs(CPURISCVState *env, hwaddr addr,
                          target_ulong size, int privs,
                          int *allowed_privs, target_ulong mode) {
    // SMMTT configuration
    int levels = 0;
    smmtt_mtt_entry_t entry = {
            .raw = 0,
    };

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

    ret = smmtt_decode_mttp(env, &levels);
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

    curr = (hwaddr) get_field(env->mttp, MTTP_PPN) << PGSHIFT;

    for (; levels > 0 && !done; levels--) {
        idx = get_field(addr, masks[levels]);
        curr = curr + idx * sizeof(target_ulong);
        entry.raw = address_space_ldq(cs->as, curr, MEMTXATTRS_UNSPECIFIED, &res);
        if (res != MEMTX_OK) {
            return false;
        }

        switch (levels) {
#if defined(TARGET_RISCV64)
            case 3:
                ret = smmtt_decode_mttl3(entry.mttl3, &curr, &done);
                if (ret < 0) {
                    return false;
                }
                break;
#endif

            case 2:
                ret = smmtt_decode_mttl2(addr, entry.mttl2, allowed_privs,
                                         &curr, &done);
                if (ret < 0) {
                    return false;
                }
                break;

            case 1:
                ret = smmtt_decode_mttl1(addr, entry.mttl1, allowed_privs);
                if (ret < 0) {
                    return false;
                }
                break;

            default:
                return false;

        }
    }

    return (privs & *allowed_privs) == privs;
}
