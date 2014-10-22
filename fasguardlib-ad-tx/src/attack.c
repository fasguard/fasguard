#include <fasguardlib-ad-tx.h>

struct fasguard_attack_output
{
    // TODO
};

struct fasguard_attack_group
{
    struct fasguard_attack_output * attack_output;
    // TODO
};

struct fasguard_attack_instance
{
    struct fasguard_attack_group * attack_group;
    // TODO
};

fasguard_attack_output_t fasguard_open_attack_output(
    char const * directory,
    fasguard_option_t const * options)
{
    for (size_t i = 0;
        options != NULL && !FASGUARD_IS_END_OF_OPTIONS(options[i]);
        ++i)
    {
        switch (options[i].key)
        {
            default:
                // TODO: log or note the error
                return NULL;
        }
    }

    // TODO
    (void)directory;
    return NULL;
}

bool fasguard_close_attack_output(
    fasguard_attack_output_t _output)
{
    struct fasguard_attack_output * output = (struct fasguard_attack_output *)_output;

    // TODO
    (void)output;
    return false;
}

fasguard_attack_group_t fasguard_start_attack_group(
    fasguard_attack_output_t _output,
    fasguard_option_t const * options)
{
    struct fasguard_attack_output * output = (struct fasguard_attack_output *)_output;

    for (size_t i = 0;
        options != NULL && !FASGUARD_IS_END_OF_OPTIONS(options[i]);
        ++i)
    {
        switch (options[i].key)
        {
            default:
                // TODO: log or note the error
                return NULL;
        }
    }

    // TODO
    (void)output;
    return NULL;
}

bool fasguard_end_attack_group(
    fasguard_attack_group_t _group)
{
    struct fasguard_attack_group * group = (struct fasguard_attack_group *)_group;

    // TODO
    (void)group;
    return false;
}

fasguard_attack_instance_t fasguard_start_attack_instance(
    fasguard_attack_group_t _group,
    fasguard_option_t const * options)
{
    struct fasguard_attack_group * group = (struct fasguard_attack_group *)_group;

    for (size_t i = 0;
        options != NULL && !FASGUARD_IS_END_OF_OPTIONS(options[i]);
        ++i)
    {
        switch (options[i].key)
        {
            default:
                // TODO: log or note the error
                return NULL;
        }
    }

    // TODO
    (void)group;
    return NULL;
}

bool fasguard_end_attack_instance(
    fasguard_attack_instance_t _instance)
{
    struct fasguard_attack_instance * instance =
        (struct fasguard_attack_instance *)_instance;

    // TODO
    (void)instance;
    return false;
}

bool add_packet_to_attack_instance(
    fasguard_attack_instance_t _instance,
    size_t packet_length,
    uint8_t const * packet,
    fasguard_option_t const * options)
{
    struct fasguard_attack_instance * instance =
        (struct fasguard_attack_instance *)_instance;

    for (size_t i = 0;
        options != NULL && !FASGUARD_IS_END_OF_OPTIONS(options[i]);
        ++i)
    {
        switch (options[i].key)
        {
            default:
                // TODO: log or note the error
                return NULL;
        }
    }

    // TODO
    (void)instance;
    (void)packet_length;
    (void)packet;
    return false;
}
