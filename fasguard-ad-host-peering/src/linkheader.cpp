/**
    @file
*/

#include <arpa/inet.h>


size_t layer2_hlen_ethernet(
    size_t len,
    uint8_t const * packet)
{
    if (len < 14)
    {
        // The ethernet header was truncated.
        return len;
    }

    // Ethertype, length, or Tag Protocol Identifier
    uint16_t ethertypeish = ntohs(*(uint16_t *)(packet + 12));
    if (ethertypeish == 0x8100)
    {
        // 802.1Q tag is present
        if (len < 18)
        {
            return len;
        }
        else
        {
            return 18;
        }
    }
    else
    {
        return 14;
    }
}

size_t layer2_hlen_raw(
    size_t len,
    uint8_t const * packet)
{
    (void)len;
    (void)packet;
    return 0;
}

size_t layer2_hlen_linux_cooked(
    size_t len,
    uint8_t const * packet)
{
    (void)len;
    (void)packet;
    return 16;
}
