#ifndef LIBFASGUARDFILTER_BLOOMFILTER_H
#define LIBFASGUARDFILTER_BLOOMFILTER_H

#include <inttypes.h>
#include <limits>
#include <string>
#include <vector>
#include <map>
#include "fasguardfilter.hpp"
#include <boost/log/trivial.hpp>

namespace fasguard
{
  /**
     @brief Parameters for a #bloom_filter.
  */
  class bloom_filter_parameters : public serializable_filter_parameters
  {
  public:
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
       @brief Create optimal parameters for a given probability of
       false positives and estimate of total number of items.
    */
    bloom_filter_parameters(
                            size_t items,
                            double probability_false_positive,
                            int ip_protocol_num,
                            int port_num,
                            int min_ngram_size,
                            int max_ngram_size);

    bloom_filter_parameters(const std::map<std::string,std::string>
                            &bf_properties);

    virtual ~bloom_filter_parameters();

    /**
       @brief Estimate the false positive rate, given the number of
       distinct items that have already been inserted.

       This is the probability that testing a single, randomly chosen
       item will return positive.
    */
    double probability_false_positive(size_t items)
        const;

    // TODO: implement
    virtual std::string to_string() const;

    // TODO: implement
    virtual bool serialize(
                           void * buffer,
                           size_t & offset,
                           size_t length)
      const;

    // TODO: implement
    virtual bool unserialize(
                             void const * buffer,
                             size_t & offset,
                             size_t length);

    num_hashes_type getNumHashes() const
    {
      return m_num_hashes;
    }

    index_type getBitLength() const
    {
      // BOOST_LOG_TRIVIAL(debug) << "bitlength in getBitLength: " <<
      //        bitlength << std::endl;
      return bitlength;
    }

    bool serialize(std::string &serialized_header);

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
    int m_ip_protocol_num;
    int m_port_num;
    /**
       @brief Number of bits in the bloom filter.
    */
    index_type bitlength;

    /**
       @brief Number of hashes used in the bloom filter.
    */
    num_hashes_type m_num_hashes;
    int m_min_ngram_size;
    int m_max_ngram_size;
  };

  /**
     @brief Statistics for a #bloom_filter.
  */
  class bloom_filter_statistics : public serializable_filter_statistics
  {
  public:
    bloom_filter_statistics();

    // TODO: implement
    virtual bool serialize(
                           void * buffer,
                           size_t & offset,
                           size_t length)
      const;

    // TODO: implement
    virtual bool unserialize(
                             void const * buffer,
                             size_t & offset,
                             size_t length);

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
  };

  /**
     @brief Bloom filter.
  */
  class bloom_filter : public file_backed_filter
  {
  public:
    /**
       @brief Constructor.
    */
    bloom_filter(
                 bloom_filter_parameters  *parameters_,
                 bloom_filter_statistics  *statistics_);

    bloom_filter(std::string filename);

    virtual ~bloom_filter();

    // TODO: implement
    virtual std::string to_string() const;

    // TODO: implement. make sure to use statistics callbacks if statistics != NULL
    virtual void insert(
                        uint8_t const * data,
                        size_t length);

    // TODO: implement. make sure to use statistics callbacks if statistics != NULL
    virtual bool insert_all(
                            filter const & other);

    // TODO: implement. make sure to use statistics callbacks if statistics != NULL
    virtual bool contains(
                          uint8_t const * data,
                          size_t length);

    bool flush();

    const int CHAR_SIZE_BITS = 8;

  protected:
    virtual void create_filter_statistics()
    {
      delete statistics;
      statistics = new bloom_filter_statistics();
    }

    /**
       @brief Set the specified bit.
    */
    inline void bit_set(
                        bloom_filter_parameters::index_type index)
    {
      uint8_t * data = (uint8_t *)access(index / 8, 1);
      // TODO: handle case when data == NULL
      *data |= 1 << (index % 8);
      commit(); // TODO: check return value
    }

    /**
       @brief Test the specified bit.
    */
    inline bool bit_test(
                         bloom_filter_parameters::index_type index)
      const
    {
      uint8_t const * data = (uint8_t const *)access_const(index / 8, 1);
      // TODO: handle case when data == NULL
      bool const ret = *data & (1 << (index % 8));
      commit();
      return ret;
    }

    /**
       @brief Test, then set the specified bit.
    */
    inline bool bit_testset(
                            bloom_filter_parameters::index_type index)
    {
      uint8_t * data = (uint8_t *)access(index / 8, 1);
      uint_fast8_t const mask = 1 << (index % 8);
      bool const ret = *data & mask;
      *data |= mask;
      commit(); // TODO: check return value
      return ret;
    }

  private:
    bloom_filter();

    bloom_filter(
                 bloom_filter const & other);

    bloom_filter & operator=(
                             bloom_filter const & other);
    std::vector<uint8_t> mBloomFilter;
  };

}

#endif
