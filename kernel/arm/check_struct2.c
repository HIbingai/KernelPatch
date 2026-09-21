#include <stddef.h>
#include "../base/setup.h"
volatile size_t vals[5] = {
    sizeof(setup_preset_t),
    offsetof(setup_preset_t, setup_offset),
    offsetof(setup_preset_t, map_offset),
    offsetof(setup_preset_t, paging_init_offset),
    offsetof(setup_preset_t, printk_offset),
};
