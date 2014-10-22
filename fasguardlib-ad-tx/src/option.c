#include <fasguardlib-ad-tx.h>

fasguard_option_t const fasguard_end_of_options = {
    .flags = FASGUARD_OPTFLAG_END_OF_OPTIONS,
    .reserved = 0,
    .key = 0,
    .value = { .uint_val = 0 },
};
