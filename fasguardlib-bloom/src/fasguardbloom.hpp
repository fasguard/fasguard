#ifndef LIBFASGUARDBLOOM_FASGUARDBLOOM_H
#define LIBFASGUARDBLOOM_FASGUARDBLOOM_H

// TODO: Figure out how to include inttypes and stdlib.
// On some systems, there are issues with cfoo headers requiring C++11
// support. Consider using the cfoo variants and adding flags to
// CXXFLAGS to enable C++11 support; or include the foo.h variants
// instead to avoid the issue entirely. See this bug for an example
// error message:
// https://bugs.launchpad.net/libmemcached/+bug/1328985
//#include <cinttypes>
//#include <cstdlib>
#include <inttypes.h>
#include <stdlib.h>

namespace fasguard
{

/**
    @brief Metadata about a bloom filter.

    This class serves two related purposes. The first is to represent
    in memory the parameters of a bloom filter. The second is to
    represent the header of a bloom filter on disk.

    All integers are stored on disk in fixed-width network byte order
    fields. An integer of type uint_fasguardN_t is stored in exactly N
    bits on disk.
*/
class bloom_filter_parameters
{
public:
    /**
        @brief Current and past bloom filter versions.

        Whenever the on-disk format is changed in a backwards-
        incompatible way, a new version number must be used.

        On disk, this is stored as a single unsigned byte.
    */
    enum Version
    {
        v0 = 0,

        reserved = 255,
    };

    /**
        @brief Type to use for the length (in bits) of a bloom filter
            or the index (in bits) into a bloom filter's data.
    */
    typedef uint_fast64_t index_type;

    /**
        @brief Type to use for the number of hashes in use.
    */
    typedef uint_fast64_t num_hashes_type;

    /**
        @brief Default constructor.

        Only #version is initialized. All other fields must be
        initialized seperately.
    */
    bloom_filter_parameters()
    :
        version(v0)
    {
    }

    /**
        @brief Create optimal parameters for a given probability of
            false positives and estimate of total number of items.
    */
    bloom_filter_parameters(
        size_t items,
        double probability_false_positive);

    /**
        @brief Estimate the false positive rate, given the number of
            distinct items that have already been inserted.

        This is the probability that testing a single, randomly chosen
        item will return positive.
    */
    double probability_false_positive(
        size_t items)
        const;

    /**
        @brief Version of the bloom filter.
    */
    Version version;

    // 7 bytes of padding go here on disk

    /**
        @brief Number of bits in the bloom filter.
    */
    index_type bitlength;

    /**
        @brief Number of hashes used in the bloom filter.
    */
    num_hashes_type num_hashes;

    // 8 bytes of padding go here on disk
    // TODO: The current implementation uses predictable hashes. If we
    // care about attacks against the hash predictability, we could
    // replace the 8 bytes of padding with a random 8-byte global
    // seed. Then factor that seed into all the hash calculations.
};

/**
    @brief Bloom filter data structure.

    @todo Figure out error handling. Return values? Exceptions? Errno?
*/
class bloom_filter
{
public:
    /**
        @brief Create a file-backed bloom filter.

        If the file already exists, open it as a bloom filter.
        Otherwise, create a new bloom filter with the specified
        parameters and create the backing file.

    */
    bloom_filter(
        bloom_filter_parameters const & parameters,
        char const * filename);

    /**
        @brief Make a copy of a bloom filter with a new backing file.

        The specified file must not already exist.
    */
    bloom_filter(
        bloom_filter const & other,
        char const * filename);

    /**
        @brief Flush the data to the backing file, if there is one.
    */
    void flush();

    /**
        @brief Insert data, and return true iff the data was already
            in the bloom filter.

        @sa insert_no_test
    */
    bool insert(
        uint8_t const * data,
        size_t length);

    /**
        @brief Insert the data, without first testing for membership.

        @sa insert
    */
    void insert_no_test(
        uint8_t const * data,
        size_t length);

    /**
        @brief Return true iff the bloom filter probably contains the
            data.
    */
    bool contains(
        uint8_t const * data,
        size_t length)
        const;

    /**
        @brief Add all elements from the other bloom filter into this
            one.
    */
    void operator|=(
        bloom_filter const & other);

    /**
        @brief Destructor.

        @todo We might also need a close function. Is a destructor
            allowed to throw an exception?
    */
    virtual ~bloom_filter();

    /**
        @brief Parameters for this bloom filter.
    */
    bloom_filter_parameters const parameters;

private:
    bloom_filter();

    bloom_filter(
        bloom_filter const & other);

    bloom_filter & operator=(
        bloom_filter const & other);
};

}

#endif
