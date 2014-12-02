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

    friend class filter;

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

    friend class filter;

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
    filter(
        filter const & other);

    filter & operator=(
        filter const & other);
};

}
