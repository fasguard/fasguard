/**
    @file
    @brief Functions for working with link-layer headers.
*/

#ifndef HOST_PEERING_LINKHEADER_H
#define HOST_PEERING_LINKHEADER_H

#include <cinttypes>

/**
    @brief Function pointer type to determine the layer 2 header length for the
           given packet.

    @param[in] len Captured length of the packet. (This may be shorter than the
                   acutal length on the wire.)
    @param[in] packet The packet itself, starting at the layer 2 header.
    @return The length of the layer 2 header.
*/
typedef size_t (*layer2_hlen_t)(
    size_t len,
    uint8_t const * packet);

/** @brief #layer2_hlen_t for ethernet. */
size_t layer2_hlen_ethernet(
    size_t len,
    uint8_t const * packet);

/** @brief #layer2_hlen_t for no layer 2 header at all. */
size_t layer2_hlen_raw(
    size_t len,
    uint8_t const * packet);

#endif
