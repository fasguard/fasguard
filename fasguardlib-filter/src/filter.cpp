// Make sure to get enough out of inttypes.h
#define __STDC_FORMAT_MACROS
#define __STDC_LIMIT_MACROS

#include <cstdio>
#include <cstring>
#include <inttypes.h>

#include <fasguardfilter.hpp>

namespace fasguard
{

bool serializable_filter_header::serialize(
    void * buffer,
    size_t & offset,
    size_t length)
    const
{
    (void)buffer;
    (void)offset;
    (void)length;
    return true;
}

bool serializable_filter_header::unserialize(
    void const * buffer,
    size_t & offset,
    size_t length)
{
    (void)buffer;
    (void)offset;
    (void)length;
    return true;
}

void serializable_filter_header::error_out_of_space(
    size_t offset,
    size_t length,
    char const * header,
    uintmax_t header_version,
    char const * field,
    bool serialize)
    const
{
    snprintf(
        serialize_error_string, sizeof(serialize_error_string),
        "%s header %s version %" PRIuMAX ", %s%s%s"
        "at offset %zu in buffer of length %zu",
        (serialize ? "insufficient space to write" : "truncated"),
        header,
        header_version,
        (field == NULL ? "" : "field "),
        (field == NULL ? "" : field),
        (field == NULL ? "" : ", "),
        offset,
        length);
}

void serializable_filter_header::error_version(
    size_t offset,
    size_t length,
    char const * header,
    uintmax_t header_version)
    const
{
    (void)length;
    snprintf(
        serialize_error_string, sizeof(serialize_error_string),
        "unsupported version (%" PRIuMAX ") for header %s "
        "at offset %zu",
        header_version,
        header,
        offset);
}


std::string filter_parameters::to_string() const
{
    static std::string const ret("no_parameters");
    return ret;
}

filter_parameters::~filter_parameters()
{
}


serializable_filter_parameters::~serializable_filter_parameters()
{
}

bool serializable_filter_parameters::serialize(
    void * buffer,
    size_t & offset,
    size_t length)
    const
{
    static char const hdr[] = "serializable_filter_parameters";
    static uint8_t const ver = SERIALIZE_V0;

    return (
        // version
        serialize_datum(
            hdr, ver, "version",
            buffer, offset, length,
            ver) &&

        // parent classes
        serializable_filter_header::serialize(
            buffer, offset, length) &&

        true);
}

bool serializable_filter_parameters::unserialize(
    void const * buffer,
    size_t & offset,
    size_t length)
{
    static char const hdr[] = "serializable_filter_parameters";

    // version
    uint8_t ver;
    if (!unserialize_datum(
        hdr, SERIALIZE_LATEST, "version",
        buffer, offset, length,
        ver))
    {
        return false;
    }

    if (ver != SERIALIZE_V0)
    {
        error_version(offset, length, hdr, ver);
        return false;
    }

    return (
        // parent classes
        serializable_filter_header::unserialize(
            buffer, offset, length) &&

        true);
}


std::string filter_statistics::to_string() const
{
    static char const format[] =
        "default_statistics["
        "insertions = %" PRIuFAST64 ", "
        "unique_insertions = %" PRIuFAST64 "]";
    static size_t const buflen =
        sizeof(format) +
        32 /* > digits in PRIuFAST64 */ * 2 /* count of PRIuFAST64 */;

    char * buf = new char[buflen];

    snprintf(buf, buflen, format, insertions, unique_insertions);

    std::string ret(buf);

    delete[] buf;

    return ret;
}

filter_statistics::~filter_statistics()
{
}

filter_statistics::filter_statistics()
:
    insertions(0),
    unique_insertions(0)
{
}

void filter_statistics::on_insert(
    uint8_t const * data,
    size_t length,
    bool unique)
{
    (void)data;
    (void)length;

    if (insertions < UINT_FAST64_MAX)
    {
        ++insertions;
    }

    if (unique && unique_insertions < UINT_FAST64_MAX)
    {
        ++unique_insertions;
    }
}

void filter_statistics::on_insert_all(
    filter_statistics const * other)
{
    if (other == NULL)
    {
        return;
    }

    /**
        @brief Set <tt>left</tt> to <tt>min(left + right, max)</tt>.

        This is similar to <tt>left += right</tt>, but takes the upper
        limit of <tt>left</tt> into account.
    */
    #define CAPPED_INCREMENT(left, right, max) \
        do \
        { \
            if ((left) >= (max) - (right)) \
            { \
                left = (max); \
            } \
            else \
            { \
                left = (right); \
            } \
        } while (false)

    CAPPED_INCREMENT(insertions, other->insertions, UINT_FAST64_MAX);

    // This is potentially wrong, but we don't have enough information
    // to make it right.
    CAPPED_INCREMENT(unique_insertions, other->unique_insertions,
        UINT_FAST64_MAX);

    #undef CAPPED_INCREMENT
}

void filter_statistics::on_contains(
    uint8_t const * data,
    size_t length,
    bool contains)
{
    // For now, don't track this.
    (void)data;
    (void)length;
    (void)contains;
}


serializable_filter_statistics::~serializable_filter_statistics()
{
}

bool serializable_filter_statistics::serialize(
    void * buffer,
    size_t & offset,
    size_t length)
    const
{
    static char const hdr[] = "serializable_filter_statistics";
    static uint8_t const ver = SERIALIZE_V0;

    return (
        // version
        serialize_datum(
            hdr, ver, "version",
            buffer, offset, length,
            ver) &&

        // parent classes
        serializable_filter_header::serialize(
            buffer, offset, length) &&

        // member variables
        serialize_datum<uint64_t>(
            hdr, ver, "insertions",
            buffer, offset, length,
            ((insertions > UINT64_MAX) ? UINT64_MAX : insertions)) &&
        serialize_datum<uint64_t>(
            hdr, ver, "unique_insertions",
            buffer, offset, length,
            ((unique_insertions > UINT64_MAX)
                ? UINT64_MAX
                : unique_insertions)) &&

        true);
}

bool serializable_filter_statistics::unserialize(
    void const * buffer,
    size_t & offset,
    size_t length)
{
    static char const hdr[] = "serializable_filter_statistics";

    // version
    uint8_t ver;
    if (!unserialize_datum(
        hdr, SERIALIZE_LATEST, "version",
        buffer, offset, length,
        ver))
    {
        return false;
    }

    if (ver != SERIALIZE_V0)
    {
        error_version(offset, length, hdr, ver);
        return false;
    }

    return (
        // parent classes
        serializable_filter_header::unserialize(
            buffer, offset, length) &&

        // member variables
        unserialize_datum<uint_fast64_t, 8>(
            hdr, ver, "insertions",
            buffer, offset, length,
            insertions) &&
        unserialize_datum<uint_fast64_t, 8>(
            hdr, ver, "unique_insertions",
            buffer, offset, length,
            unique_insertions) &&

        true);
}


std::string filter::to_string() const
{
    static std::string const ret("unknown_filter");
    return ret;
}

bool filter::insert_all(
    filter const & other)
{
    (void)other;
    return false;
}

filter::~filter()
{
    delete parameters;
    delete statistics;
}

filter::filter(
    filter_parameters * parameters_,
    filter_statistics * statistics_)
:
    parameters(parameters_),
    statistics(statistics_)
{
}

}
