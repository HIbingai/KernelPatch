#include <stddef.h>
#include "include/preset.h"
volatile size_t vals[6] = {
    sizeof(setup_preset_t),
    offsetof(setup_preset_t, setup_offset),
    offsetof(setup_preset_t, map_offset),
    offsetof(setup_preset_t, paging_init_offset),
    offsetof(setup_preset_t, printk_offset),
    offsetof(setup_preset_t, kimg_size),
};
