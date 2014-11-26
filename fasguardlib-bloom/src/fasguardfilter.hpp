// TODO: header guards

#include <inttypes.h>
#include <string>

namespace fasguard
{

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
};

/**
    @brief Base class for a filter.
*/
class filter
{
public:
    /**
        @brief Return a string that describes the filter.

        E.g., this might be
        "bloom_filter[bloom_filter_parameters[bitlength = 1024, num_hashes = 5], bits_set = 123, false_positive_rate = 0.00123]"
        for a bloom filter.
    */
    virtual std::string to_string() const;

    /**
        @brief Insert data, and return true iff the data was already
            in the filter.

        @note Non-abstract derived classes must implement at least one
            of this and #insert_no_test.

        @sa insert_no_test
    */
    virtual bool insert(
        uint8_t const * data,
        size_t length);

    /**
        @brief Insert the data, without first testing for membership.

        @note Non-abstract derived classes must implement at least one
            of this and #insert.

        @sa insert
    */
    virtual void insert_no_test(
        uint8_t const * data,
        size_t length);

    /**
        @brief If possible, add all elements from the other filter
            into this one.

        If the filters are compatible, add all the elements from the
        other filter into this one and return true. Otherwise, make no
        changes to this filter and return false.

        @note The two filters must be of the same derived class.
    */
    virtual bool insert_all(
        filter const & other);

    /**
        @brief Return true iff the filter (probably) contains the
            data.

        @note Non-abstract derived classes must implement this.
    */
    virtual bool contains(
        uint8_t const * data,
        size_t length)
        const;

    /**
        @brief Destructor.

        @note Derived classes' destructors must call this.
    */
    virtual ~filter();

    /**
        @brief Parameters for this filter.

        @note This must be initialized by all constructors, including
            those in derived classes.
    */
    filter_parameters const * const parameters;
};

}
