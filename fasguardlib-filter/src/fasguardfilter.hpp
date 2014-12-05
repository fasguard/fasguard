#ifndef LIBFASGUARDFILTER_FASGUARDFILTER_H
#define LIBFASGUARDFILTER_FASGUARDFILTER_H

#include <inttypes.h>
#include <limits>
#include <string>

namespace fasguard
{

/**
    @brief Interface class for a serializable header to a filter
        stored on disk.

    Subclasses of #filter_parameters or #filter_statistics that
    are used by serializable filters should also subclass this.
*/
class serializable_filter_header
{
public:
    /**
        @brief Maximum size, in bytes, of all headers combined for any
            single file.
    */
    static size_t const MAX_HEADER_LENGTH = 1024 * 1024;

    /**
        @brief Serialize this object to a buffer.

        @note Derived classes must call this method for each of their
            parents that is equal to or a subclass of
            #serializable_filter_header.

        @note Every implementation of this that writes anything to
            @p buffer, should write a version number as the first
            field. This version number should be incremented every
            time the implementation changes in an incompatible way.
            There should also be at least one reserved version number
            for use to extend the version field when all other
            possible values are exhausted.

        @note Data must be stored in a way that has the same meaning
            across platforms. E.g., integers should be stored in
            network byte order.

        @param[out] buffer Where to serialize this object to.
        @param[in,out] offset On input, initial offset in @p buffer
            of where to start serialization. On output, offset to the
            end of the serialized object. If there's an error, the
            value of this is undefined.
        @param[in] length Length of @p buffer.
        @return True on success, false on failure. On failure,
            #serialize_error_string contains an error message.
    */
    virtual bool serialize(
        void * buffer,
        size_t & offset,
        size_t length)
        const;

    /**
        @brief Unserialize a buffer into this object.

        @note Derived classes must call this method for each of their
            parents that is equal to or a subclass of
            #serializable_filter_header. The order must match the
            the order used in #serialize.

        @param[in] buffer Where to unserialize this object from.
        @param[in,out] offset On input, initial offset in @p buffer
            of where to start unserialization. On output, offset to
            the end of the serialized object. If there's an error, the
            value of this is undefined.
        @param[in] length Length of @p buffer.
        @return True on success, false on failure. On failure,
            #serialize_error_string contains an error message.
    */
    virtual bool unserialize(
        void const * buffer,
        size_t & offset,
        size_t length);

    /**
        @brief String containing the last error message.

        The contents of this are only defined after an unsuccessful
        call to one of the methods defined in this class.

        This data is not (un)serialized.
    */
    mutable char serialize_error_string[256];

protected:
    serializable_filter_header();

    /**
        @brief Serialize a single integer.

        This function assumes that the integer type is encoded as
        either unsigned or twos-complement, and the value fits in the
        number of bytes allotted.

        @tparam integer_type The type of integer to serialize.
        @tparam integer_length The number of bytes of @p buffer to
            use.
        @param[in] header See #error_out_of_space.
        @param[in] header_version See #error_out_of_space.
        @param[in] field See #error_out_of_space.
        @param[out] buffer Serialization buffer.
        @param[in,out] offset Where in @p buffer to serialize the
            integer. This is incremented by integer_length.
            If there's an error, the value of this is undefined.
        @param[in] length Length of @p buffer.
        @param[in] datum Integer to serialize.
        @return True on success, false on failure. On failure,
            #serialize_error_string contains an error message.
    */
    template <
        typename integer_type,
        size_t integer_length = sizeof(integer_type)>
    bool serialize_datum(
        char const * header,
        uintmax_t header_version,
        char const * field,
        void * buffer,
        size_t & offset,
        size_t length,
        integer_type const & datum)
        const
    {
        if (offset + integer_length > length)
        {
            error_out_of_space(
                offset, length,
                header, header_version, field,
                true);
            return false;
        }

        uint8_t * bytes = (uint8_t *)buffer + offset;

        for (size_t i = 0; i < integer_length; ++i)
        {
            bytes[i] =
                (datum >> (8 * (integer_length - i - 1))) & 0xff;
        }

        offset += integer_length;
        return true;
    }

    /**
        @brief Unserialize a single integer.

        This function assumes that the integer type is encoded as
        either unsigned or twos-complement, and that
        <tt>offset + integer_length &lt;= length</tt>.

        @tparam integer_type The type of integer to unserialize.
        @tparam integer_length The number of bytes of @p buffer to
            use.
        @param[in] header See #error_out_of_space.
        @param[in] header_version See #error_out_of_space.
        @param[in] field See #error_out_of_space.
        @param[in] buffer Buffer containing the integer.
        @param[in,out] offset Where in @p buffer to unserialize the
            integer from. This is incremented by integer_length.
            If there's an error, the value of this is undefined.
        @param[in] length Length of @p buffer. This is not checked.
        @param[out] datum Result of unserializing.
        @return True on success, false on failure. On failure,
            #serialize_error_string contains an error message.
    */
    template <
        typename integer_type,
        size_t integer_length = sizeof(integer_type)>
    bool unserialize_datum(
        char const * header,
        uintmax_t header_version,
        char const * field,
        void const * buffer,
        size_t & offset,
        size_t length,
        integer_type & datum)
        const
    {
        if (offset + integer_length > length)
        {
            error_out_of_space(
                offset, length,
                header, header_version, field,
                false);
            return false;
        }

        uint8_t const * bytes = (uint8_t const *)buffer + offset;

        // Handle the trivial case first so that the below code can be
        // simpler.
        if (integer_length == 0)
        {
            datum = 0;
        }

        // Initialize datum with the correct fill bits.
        if (std::numeric_limits<integer_type>::is_signed)
        {
            if (bytes[0] & 0x80)
            {
                datum = -1;
            }
            else
            {
                datum = 0;
            }
        }
        else
        {
            datum = 0;
        }

        // Fill in bytes from the buffer.
        for (size_t i = 0; i < integer_length; ++i)
        {
            datum = (datum << 8) | bytes[i];
        }

        offset += integer_length;
        return true;
    }

    /**
        @brief Set #serialize_error_string appropriately for a
            buffer-out-of-space error.

        @param[in] offset Offset into the buffer.
        @param[in] length Length of the buffer.
        @param[in] header Name of the header being (un)serialized.
            This must not be NULL.
        @param[in] header_version Version of the header.
        @param[in] field Name of the field withing the header being
            (un)serialized. This may be NULL.
        @param[in] serialize True when serializing, false when
            unserializing.
    */
    void error_out_of_space(
        size_t offset,
        size_t length,
        char const * header,
        uintmax_t header_version,
        char const * field,
        bool serialize)
        const;

    /**
        @brief Set #serialize_error_string appropriately for an
            error trying to unserialize from an unsupported version.

        @param[in] offset Offset into the buffer.
        @param[in] length Length of the buffer.
        @param[in] header Name of the header being (un)serialized.
            This must not be NULL.
        @param[in] header_version Extracted version of the header.
    */
    void error_version(
        size_t offset,
        size_t length,
        char const * header,
        uintmax_t header_version)
        const;
};

/**
    @brief Base class for parameters for a filter.
*/
class filter_parameters
{
public:
    /**
        @brief Return a string that describes the parameters.

        E.g., this might be
        "bloom_filter_parameters[bitlength = 1024, num_hashes = 5]"
        for parameters for a bloom filter.
    */
    virtual std::string to_string() const;

    /**
        @brief Destructor.
    */
    virtual ~filter_parameters();

protected:
    /**
        @brief Default constructor.
    */
    filter_parameters();

private:
    filter_parameters(
        filter_parameters const & other);

    filter_parameters & operator=(
        filter_parameters const & other);
};

/**
    @brief Base class for #filter_parameters that are serializable.
*/
class serializable_filter_parameters
:
    public filter_parameters,
    public serializable_filter_header
{
public:
    virtual ~serializable_filter_parameters();

    virtual bool serialize(
        void * buffer,
        size_t & offset,
        size_t length)
        const;

    virtual bool unserialize(
        void const * buffer,
        size_t & offset,
        size_t length);

protected:
    serializable_filter_parameters();

private:
    /**
        @brief Type to store the serialize version.
    */
    enum serialize_version_type
    {
        SERIALIZE_V0 = 0,
        SERIALIZE_LATEST = SERIALIZE_V0,
        SERIALIZE_RESERVED = 255,
    };

    serializable_filter_parameters(
        serializable_filter_parameters const & other);

    serializable_filter_parameters & operator=(
        serializable_filter_parameters const & other);
};

/**
    @brief Base class for statistics for a filter.
*/
class filter_statistics
{
public:
    /**
        @brief Return a string that describes the statistics.

        E.g., this might be
        "bloom_filter_statistics[insertions=7, duplicate_insertions=4]"
        for statistics for a bloom filter.
    */
    virtual std::string to_string() const;

    /**
        @brief Destructor.
    */
    virtual ~filter_statistics();

    /**
        @brief Number of times an attempt was made to insert an item
            into the filter.

        If this is greater than or equal to UINT64_MAX, further
        insertions may be counted, but the count may be reset to
        UINT64_MAX if the filter is saved to disk and loaded back
        again. If it's is equal to UINT_FAST64_MAX, no further
        insertions will be counted.
    */
    uint_fast64_t insertions;

    /**
        @brief Number of items inserted into the filter that were not
            already present in the filter.

        The note in about upper limits in #insertions applies to this
        field too.

        @note This number may be way too large if two or more filters
            are merged, e.g., with #filter::insert_all.
    */
    uint_fast64_t unique_insertions;

protected:
    /**
        @brief Default constructor.
    */
    filter_statistics();

    /**
        @brief Callback for #filter::insert.

        @param[in] data Data that was inserted.
        @param[in] length Length of @p data.
        @param[in] unique True if the data was (probably) not already
            present in the filter; false if the data was (probably)
            already in the filter.
    */
    virtual void on_insert(
        uint8_t const * data,
        size_t length,
        bool unique);

    /**
        @brief Callback for #filter::insert_all.

        @param[in] other Statistics from the other filter. This may be
            NULL, however these statistics will not be correct if this
            is NULL.
    */
    virtual void on_insert_all(
        filter_statistics const * other);

    /**
        @brief Callback for #filter::contains.

        @param[in] data Data that was tested.
        @param[in] length Length of @p data.
        @param[in] contains Result of the #filter::contains test.
    */
    virtual void on_contains(
        uint8_t const * data,
        size_t length,
        bool contains);

private:
    filter_statistics(
        filter_statistics const & other);

    filter_statistics & operator=(
        filter_statistics const & other);
};

/**
    @brief Serializable version of #filter_statistics.
*/
class serializable_filter_statistics
:
    public filter_statistics,
    public serializable_filter_header
{
public:
    virtual ~serializable_filter_statistics();

    virtual bool serialize(
        void * buffer,
        size_t & offset,
        size_t length)
        const;

    virtual bool unserialize(
        void const * buffer,
        size_t & offset,
        size_t length);

protected:
    /**
        @brief Default constructor.
    */
    serializable_filter_statistics();

private:
    serializable_filter_statistics(
        serializable_filter_statistics const & other);

    serializable_filter_statistics & operator=(
        serializable_filter_statistics const & other);

    /**
        @brief Type to store the serialize version.
    */
    enum serialize_version_type
    {
        SERIALIZE_V0 = 0,
        SERIALIZE_LATEST = SERIALIZE_V0,
        SERIALIZE_RESERVED = 255,
    };
};

/**
    @brief Base class for a filter.
*/
class filter
{
public:
    /**
        @brief Return a string that describes the filter.

        This should not include information that's already in the
        filter's parameters or statistics.

        E.g., this might be
        "bloom_filter[bits_set = 123, false_positive_rate = 0.00123]"
        for a bloom filter.
    */
    virtual std::string to_string() const;

    /**
        @brief Insert data.

        @note All implementations of this method should call
            #filter_statistics::on_insert iff #statistics is not NULL.
            Derived classes should not call their parent's
            implementation of this, to avoid duplicate calls to
            #filter_statistics::on_insert.
    */
    virtual void insert(
        uint8_t const * data,
        size_t length)
        = 0;

    /**
        @brief If possible, add all elements from the other filter
            into this one.

        If the filters are compatible, add all the elements from the
        other filter into this one and return true. Otherwise, make no
        changes to this filter and return false.

        If a derived class does not override this, the default
        implementation always returns false.

        @note The two filters must be of the same derived class.

        @note All implementations of this method should call
            #filter_statistics::on_insert_all iff #statistics is not
            NULL and insertion is possible. Derived classes should
            not call their parent's implementation of this, to avoid
            duplicate calls to #filter_statistics::on_insert_all.
    */
    virtual bool insert_all(
        filter const & other);

    /**
        @brief Return true iff the filter (probably) contains the
            data.

        @note All implementations of this method should call
            #filter_statistics::on_contains iff #statistics is not
            NULL. Derived classes should not call their parent's
            implementation of this, to avoid duplicate calls to
            #filter_statistics::on_contains.
    */
    virtual bool contains(
        uint8_t const * data,
        size_t length)
        const
        = 0;

    /**
        @brief Destructor.

        @note Derived classes' destructors must call this.
    */
    virtual ~filter();

    /**
        @brief Parameters for this filter.
    */
    filter_parameters const * const parameters;

    /**
        @brief Statistics for this filter.

        This may be NULL.

        The statistics may be updated even when <tt>this</tt> is
        const.
    */
    filter_statistics * const statistics;

protected:
    /**
        @brief Constructor.

        @param[in] parameters_ Parameters for this filter. This must
            not be NULL. This is deleted by #~filter.
        @param[in] statistics_ Default-constructed statistics of the
            correct derived type. This may be NULL to indicate that
            tracking of statistics is not desired. This is deleted by
            #~filter.
    */
    filter(
        filter_parameters const * parameters_,
        filter_statistics * statistics_);

private:
    filter();

    filter(
        filter const & other);

    filter & operator=(
        filter const & other);
};

}

#endif
