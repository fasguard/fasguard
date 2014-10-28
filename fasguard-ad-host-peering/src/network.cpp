#include <arpa/inet.h>
#include <boost/functional/hash.hpp>
#include <cstring>

#include "network.hpp"


size_t const IPAddress::LENGTHS[] = {
    4, // IPv4
    16, // IPv6
};

int const IPAddress::DOMAINS[] = {
    AF_INET, // IPv4
    AF_INET6, // IPv6
};

bool IPAddress::parse_packet(
    IPAddress & src,
    IPAddress & dst,
    size_t packet_length,
    uint8_t const * packet)
{
    // Determine the IP version and address field offsets.
    IPAddress::Version ip_version;
    size_t src_address_offset;
    size_t dst_address_offset;
    if (packet_length >= 20 && IP_VERSION(packet) == 4)
    {
        ip_version = IPAddress::IPv4;
        src_address_offset = 12;
        dst_address_offset = 16;
    }
    else if (packet_length >= 40 && IP_VERSION(packet) == 6)
    {
        ip_version = IPAddress::IPv6;
        src_address_offset = 8;
        dst_address_offset = 24;
    }
    else
    {
        return false;
    }

    // Extract the IP addresses.
    src.mVersion = ip_version;
    memcpy(
        src.mBytes,
        packet + src_address_offset,
        IPAddress::LENGTHS[ip_version]);

    dst.mVersion = ip_version;
    memcpy(
        dst.mBytes,
        packet + dst_address_offset,
        IPAddress::LENGTHS[ip_version]);

    return true;
}

IPAddress::IPAddress(
    IPAddress::Version version,
    uint8_t const * buffer,
    size_t offset)
:
    mVersion(version)
{
    memcpy(mBytes, buffer + offset, IPAddress::LENGTHS[version]);
}

bool IPAddress::operator==(
    IPAddress const & other) const
{
    return mVersion == other.mVersion &&
        memcmp(mBytes, other.mBytes, IPAddress::LENGTHS[mVersion]) == 0;
}

IPAddress::Version IPAddress::getVersion() const
{
    return mVersion;
}

size_t IPAddress::getLength() const
{
    return IPAddress::LENGTHS[getVersion()];
}

uint8_t const * IPAddress::getBytes() const
{
    return mBytes;
}

std::string IPAddress::toString() const
{
    char s[INET6_ADDRSTRLEN];
    inet_ntop(IPAddress::DOMAINS[mVersion], mBytes, s, INET6_ADDRSTRLEN);
    return std::string(s);
}

namespace std
{
    size_t hash<IPAddress>::operator()(
        ::IPAddress const & addr) const
    {
        size_t seed = 0;

        ::boost::hash_combine(seed, addr.getVersion());

        for (size_t i = 0; i < addr.getLength(); ++i)
        {
            ::boost::hash_combine(seed, addr.getBytes()[i]);
        }

        return seed;
    }
}
