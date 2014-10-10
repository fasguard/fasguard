//#include <boost/functional/hash.hpp> // TODO: uncomment this once we have the autoconf macros for boost
#include <cstring>

#include "network.hpp"


size_t const IPAddress::LENGTHS[] = {
    4, // IPv4
    16, // IPv6
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

namespace std
{
    size_t hash<::IPAddress>::operator()(
        ::IPAddress const & addr) const
    {
        // TODO: remove the dummy implementation once boost is working
        #if 0
        size_t seed = 0;

        ::boost::hash_combine(seed, addr.getVersion());

        for (size_t i = 0; i < addr.getLength(); ++i)
        {
            ::boost::hash_combine(seed, addr.getBytes()[i]);
        }

        return seed;
        #else
        (void)addr;
        return 0;
        #endif
    }
}
