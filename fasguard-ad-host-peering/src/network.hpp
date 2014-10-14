/**
    @file
    @brief Data types for network primitives.
*/

#ifndef _HOST_PEERING_NETWORK_H
#define _HOST_PEERING_NETWORK_H

#include <cinttypes>
#include <functional>
#include <string>


/**
    @brief Extract the version field from a pointer to the beginning of an IP
           packet.
*/
#define IP_VERSION(packet) (((packet)[0] & 0xf0) >> 4)

/**
    @brief Class to represent a single IP address (v4 or v6).
*/
class IPAddress
{
public:
    /**
        @brief Version of the IP address.

        @sa LENGTHS
    */
    enum Version
    {
        IPv4,
        IPv6,
    };

    /**
        @brief Mapping from #Version to the length of that version's addresses.

        @sa Version
    */
    static size_t const LENGTHS[];

    /**
        @brief Mapping from #Version to the appropriate socket domain (e.g.,
               AF_INET).

        @sa Version
    */
    static int const DOMAINS[];

    /**
        @brief Create an IPAddress from a buffer.

        @param[in] buffer Byte array containing the ip address, in network byte
                          order.
        @param[in] offset Offset into @p buffer.
        @param[in] version IP version to use. @p buffer must have a length of at
                           least <tt>offset + #LENGTHS[version]</tt>.
    */
    explicit IPAddress(
        Version version,
        uint8_t const * buffer,
        size_t offset = 0);

    /**
        @brief Compare two IPAddresses for equality.
    */
    bool operator==(
        IPAddress const & other) const;

    /**
        @brief Get the version of this address.
    */
    Version getVersion() const;

    /**
        @brief Get the length (in bytes) of this address.
    */
    size_t getLength() const;

    /**
        @brief Get the bytes of this address.
    */
    uint8_t const * getBytes() const;

    /**
        @brief Return a string representation of this address.
    */
    std::string toString() const;

protected:
    /**
        @brief Version of this IP address.
    */
    Version mVersion;

    /**
        @brief Bytes of this IP address, in network byte order.

        Note that only the first 4 bytes of this array are used for an IPv4
        address.
    */
    uint8_t mBytes[16];
};

namespace std
{
    template<>
    struct hash<::IPAddress>
    {
        /**
            @brief Compute the hash of an #IPAddress.
        */
        size_t operator()(
            ::IPAddress const & addr) const;
    };
}

#endif
