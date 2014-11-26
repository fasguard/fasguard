#include <cstdio>

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


std::string filter::to_string() const
{
    static char const format[] = "unknown_filter[%s]";

    std::string const & parameters_str = parameters->to_string();

    size_t const buflen = sizeof(format) + parameters_str.length();
    char * buf = new char[buflen];

    snprintf(buf, buflen, format, parameters_str.c_str());

    std::string ret(buf);

    delete[] buf;

    return ret;
}

bool filter::insert(
    uint8_t const * data,
    size_t length)
{
    bool const ret = contains(data, length);
    insert_no_test(data, length);
    return ret;
}

void filter::insert_no_test(
    uint8_t const * data,
    size_t length)
{
    (void)insert(data, length);
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
}

}
