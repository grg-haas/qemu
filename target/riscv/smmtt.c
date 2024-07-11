
#include "smmtt.h"

#include "qemu/log.h"
#include "qapi/error.h"
#include "trace.h"
#include "exec/exec-all.h"

/*
 * Definitions
 */

static const unsigned long long masks_rw[] = {
    MTTL1_RW_OFFS, MTTL1_RW, MTTL2_RW, MTTL3
};

static const unsigned long long masks[] = {
    MTTL1_OFFS, MTTL1, MTTL2, MTTL3,
};

/*
 * Internal helpers
 */

static int smmtt_decode_mttp(CPURISCVState *env, bool *rw, int *levels) {
    smmtt_mode_t smmtt_mode = get_field(env->mttp, MTTP_MODE);

    switch(smmtt_mode) {
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

static int smmtt_decode_mttl2(hwaddr addr, bool rw, smmtt_mtt_entry_t entry,
                              int *privs, hwaddr *next, bool *done) {
    smmtt_type_t type;
    smmtt_type_rw_t type_rw;
    target_ulong idx;

    *done = false;
    if(rw) {
        if(entry.mttl2.mttl2_rw.zero != 0) {
            *done = true;
            return 0;
        }

        type_rw = (smmtt_type_rw_t) entry.mttl2.mttl2_rw.type;
        switch(type_rw) {
            case SMMTT_TYPE_RW_1G_DISALLOW:
                *privs = 0;
                *done = true;
                break;

            case SMMTT_TYPE_RW_1G_ALLOW_RW:
                *privs |= PAGE_WRITE;
                // fall through
            case SMMTT_TYPE_RW_1G_ALLOW_R:
                *privs |= PAGE_READ;
                *done = true;
                break;

            case SMMTT_TYPE_RW_2M_PAGES:
                if(entry.mttl2.mttl2_rw.info >> 32 != 0) {
                    return -1;
                }

                idx = (addr & MTTL2_RW) >> MTTL2_2M_PAGES_SHIFT;
                switch(get_field(entry.mttl2.mttl2_rw.info, MTTL2_RW_2M_PAGES << (MTTL2_RW_2M_PAGES_BITS * idx))) {
                    case SMMTT_2M_PAGES_RW_DISALLOWED:
                        *privs = 0;
                        break;

                    case SMMTT_2M_PAGES_RW_READ_WRITE:
                        *privs |= PAGE_WRITE;
                        // fall through
                    case SMMTT_2M_PAGES_RW_READ:
                        *privs |= PAGE_READ;
                        break;

                    default:
                        return -1;
                }

                *done = true;
                break;

            case SMMTT_TYPE_RW_MTT_L1_DIR:
                *next = entry.mttl2.mttl2_rw.info << PGSHIFT;
                *done = false;
                break;

            default:
                return -1;
        }
    } else {
        if(entry.mttl2.mttl2.zero != 0) {
            return false;
        }

        type = (smmtt_type_t) entry.mttl2.mttl2.type;
        switch(type) {
            case SMMTT_TYPE_1G_DISALLOW:
                *privs = 0;
                *done = true;
                break;
            case SMMTT_TYPE_1G_ALLOW:
                *privs = (PAGE_READ | PAGE_WRITE | PAGE_EXEC);
                *done = true;
                break;

            case SMMTT_TYPE_2M_PAGES:
                if(entry.mttl2.mttl2.info >> 32 != 0) {
                    return -1;
                }

                idx = (addr & MTTL2) >> MTTL2_2M_PAGES_SHIFT;
                switch(get_field(entry.mttl2.mttl2.info, MTTL2_2M_PAGES << (MTTL2_2M_PAGES_BITS * idx))) {
                    case SMMTT_2M_PAGES_DISALLOWED:
                        *privs = 0;
                        break;

                    case SMMTT_2M_PAGES_ALLOWED:
                        *privs = (PAGE_READ | PAGE_WRITE | PAGE_EXEC);
                        break;

                    default:
                        return -1;
                }

                *done = true;
                break;

            case SMMTT_TYPE_MTT_L1_DIR:
                *next = entry.mttl2.mttl2.info << PGSHIFT;
                *done = false;
                break;
        }
    }

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
    if(!riscv_cpu_cfg(env)->ext_smmtt || (mode == PRV_M)) {
        *allowed_privs = (PAGE_READ | PAGE_WRITE | PAGE_EXEC);
        return true;
    }

    ret = smmtt_decode_mttp(env, &rw, &levels);
    if(ret < 0) {
        return false;
    }

    if(levels == -1) {
        // This must be SMMTT_BARE, so SMMTT will allow accesses here
        *allowed_privs = (PAGE_READ | PAGE_WRITE | PAGE_EXEC);
    } else {
        // Initialize allowed privileges to 0 and discover
        // what's allowed on the way.
        *allowed_privs = 0;
    }

    msk = rw ? masks_rw : masks;
    curr = (hwaddr) get_field(env->mttp, MTTP_PPN) << PGSHIFT;

    for(; levels >= 0 && !done; levels--) {
        idx = get_field(addr, msk[levels]);
        if(levels != 0) {
            // Fetch an entry
            curr = curr + idx * 8;
            entry.raw = address_space_ldq(cs->as, curr, MEMTXATTRS_UNSPECIFIED, &res);
        }

        switch (levels) {
            case 3:
                if(entry.mttl3.zero != 0) {
                    return false;
                }

                curr = entry.mttl3.mttl2_ppn << PGSHIFT;
                break;

            case 2:
                ret = smmtt_decode_mttl2(addr, rw, entry, allowed_privs,
                                         &curr, &done);
                if(ret < 0) {
                    return false;
                }
                break;

            case 1:
                // Do nothing here besides translate, and preserve
                // entry for the next go around
                break;

            case 0:
                if(rw) {
                    switch(get_field(entry.mttl1, 0b1111 << idx)) {
                        case SMMTT_MTT_L1_DIR_RW_DISALLOWED:
                            *allowed_privs = 0;
                            break;

                        case SMMTT_MTT_L1_DIR_RW_READ_WRITE:
                            *allowed_privs |= (PROT_WRITE);
                            // fall through
                        case SMMTT_MTT_L1_DIR_RW_READ:
                            *allowed_privs |= (PROT_READ);
                            break;

                        default:
                            return false;
                    }
                } else {
                    switch(get_field(entry.mttl1, 0b11 << idx)) {
                        case SMMTT_MTT_L1_DIR_DISALLOWED:
                            *allowed_privs = 0;
                            break;

                        case SMMTT_MTT_L1_DIR_ALLOWED:
                            *allowed_privs = (PROT_READ | PROT_WRITE | PROT_EXEC);
                            break;

                        default:
                            return false;
                    }
                }
                break;

            default:
                return false;

        }
    }

    // ASSUMPTION: we assume that read implies execute, and leave it up to other
    // parts of the memory hierarchy to indicate execute permissions.
    if(*allowed_privs & PROT_READ) {
        *allowed_privs |= PROT_EXEC;
    }

    return (privs & *allowed_privs) == privs;
}
