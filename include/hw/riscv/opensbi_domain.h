
#ifndef RISCV_DOMAIN_H
#define RISCV_DOMAIN_H

#include "hw/sysbus.h"
#include "qom/object.h"
#include "cpu.h"

#define TYPE_OPENSBI_MEMREGION "opensbi-memregion"
OBJECT_DECLARE_SIMPLE_TYPE(OpenSBIMemregionState, OPENSBI_MEMREGION)

#define OPENSBI_MEMREGION_DEVICES_MAX   16

struct OpenSBIMemregionState {
    /* public */
    DeviceState parent_obj;

    /* private */
    uint64_t base;
    uint32_t order;
    uint64_t size;
    bool mmio;
    char *devices[OPENSBI_MEMREGION_DEVICES_MAX];

    bool reserve;
};

#define TYPE_OPENSBI_DOMAIN "opensbi-domain"
OBJECT_DECLARE_SIMPLE_TYPE(OpenSBIDomainState, OPENSBI_DOMAIN)

#define OPENSBI_DOMAIN_MEMREGIONS_MAX   16

struct OpenSBIDomainState {
    /* public */
    DeviceState parent_obj;

    /* private */
    OpenSBIMemregionState *regions[OPENSBI_DOMAIN_MEMREGIONS_MAX];
    unsigned int region_perms[OPENSBI_DOMAIN_MEMREGIONS_MAX];
    unsigned long first_possible_hart, last_possible_hart;
    unsigned int boot_hart;
    uint64_t next_arg1;
    uint64_t next_addr;
    uint32_t next_mode;
    bool system_reset_allowed;
    bool system_suspend_allowed;
    uint32_t smmtt_mode;

    bool assign;
};

void create_fdt_opensbi_domains(MachineState *s);

#endif /* RISCV_DOMAIN_H */
