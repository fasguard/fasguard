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
    size_t hash<::IPAddress>::operator()(
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
