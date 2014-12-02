// Make sure to get enough out of inttypes.h
#define __STDC_FORMAT_MACROS
#define __STDC_LIMIT_MACROS

#include <cstdio>
#include <inttypes.h>

#include <fasguardfilter.hpp>

namespace fasguard
{

std::string filter_parameters::to_string() const
{
    static std::string const ret("no_parameters");
    return ret;
}

filter_parameters::~filter_parameters()
{
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
    filter_parameters const * parameters_,
    filter_statistics * statistics_)
:
    parameters(parameters_),
    statistics(statistics_)
{
}

}
