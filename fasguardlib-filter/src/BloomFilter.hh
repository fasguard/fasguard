#ifndef BLOOM_FILTER_HH
#define BLOOM_FILTER_HH
#include <vector>
#include <fstream>
#include <boost/shared_ptr.hpp>
#include <boost/unordered_map.hpp>
#include "lru_cache_using_std.h"
#include "BenignNgramStorage.hh"

/**
 * @brief Stores data for caching of Bloom hash lookup.
 */
class HashVals
{
public:
  HashVals(boost::shared_ptr<std::vector<uint64_t> > bit_indeces);
protected:
  boost::shared_ptr<std::vector<uint64_t> > m_bit_indeces;
};

/**
 * @brief Functor to pass to hash
 */
class CalcBitIndeces
{
public:
  CalcBitIndeces(size_t num_hash_func, uint64_t filter_size_in_bits);
  CalcBitIndeces()
  {}
  boost::shared_ptr<std::vector<uint64_t> >
  operator()(const std::string &ngram);
protected:
  size_t m_num_hash_func;
  uint64_t m_filter_size_in_bits;
};
//boost::shared_ptr<std::vector<uint64_t> >
//calcBitIndeces(std::string ngram);
/**
 * @brief Implementation of Bloom filter for ngrams.
 *
 * This stores a Bloom filter for a range of ngram sizes from the payload of
 * large numbers of packets for a single TCP or UDP service.
 */
class BloomFilter : public BenignNgramStorage
{
public:
  /**
   * Constructor. This accepts parameters that specify the benign traffic
   * to be stored in the Bloom filter as well as parameters for the sizing of
   * the Bloom filter. This constructor is used for the initial construction
   * of a BloomFilter object, not restoring a BloomFilter object from
   * persistant store.
   * @param projected_items Number of items that will potentially be inserted
   *    into the Bloom filter. Used for Bloom filter sizing.
   * @param probability_false_positive Desired probability of false postive for
   *    the Bloom filter. Used for Bloom filter sizing.
   * @param ip_protocol_num This is the protocol field number that appears in
   *    the ip header.
   * @param port_num The tcp or udp port number of the captured traffic.
   * @param min_ngram_size The minimum number of bytes in a stored ngram.
   * @param max_ngram_size The maximum number of bytes in a stored ngram.
   */
  BloomFilter(size_t inserted_items, double probability_false_positive,
              int ip_protocol_num, int port_num, int min_ngram_size,
              int max_ngram_size);
  /**
   * Constructor for restoring Bloom filter from persistent store.
   * @param filename Name of file containing persistent Bloom filter.
   * @param from_mem_p If true, Bloom filter data is loaded in memory. If
   *    false, file is accesed for each Bloom filter bit using fseek.
   */
  BloomFilter(const std::string &filename,bool from_mem_p);
  /**
   * Destructor.
   */
  ~BloomFilter();
  /**
   * Insert ngrams extracted from a string into the storage data structure.
   * @param data The content from the packet.
   * @param length The length of data.
   */
  virtual void insert(uint8_t const * data, size_t length);

  /**
   * Check to see if a string is stored in the data structure. Typically, the
   * string is an ngram.
   * @param data The string to search for.
   * @param length The length of data.
   */
  virtual bool contains(uint8_t const * data, size_t length);

  /**
   * Flush the data structure to a file.
   * @param filename Name of file used for persistence.
   */
  virtual bool flush(std::string filename);

  /**
   * Returns the first value in the Bloom filter that's above the input value.
   * Used only for testing.
   * @param val Input value to compare to.
   * @return First value above val.
   */
  unsigned int entryAbove(unsigned int val);

  /**
   * Writes out a Bloom filter that is a combination of the current BloomFilter
   * and a BloomFilter given as a first argument.
   * @param other Other Bloom filter to combine with.
   * @param output_file Filename into which result Bloom Filter will be written.
   */
  void WriteCombined(BloomFilter &other,std::string output_file);
  static const unsigned int MAX_HASHES = 512;
  static const unsigned int CHAR_SIZE_BITS = 8;
  static const uint32_t HeaderLengthInBytes = 4096;
  static const unsigned int NUM_CACHE_ENTRIES = 10000;

  /**
     @brief Type to use for the length (in bits) of a bloom filter
     or the index (in bits) into a bloom filter's data.
  */
  typedef uint_fast64_t index_type;
  /**
     @brief Type to use for the number of hashes in use.
  */
  typedef uint_fast64_t num_hashes_type;

protected:
  /**
     @brief Number of bits in the bloom filter.
  */
  index_type m_bitlength;

  /**
     @brief Number of hashes used in the bloom filter.
  */
  num_hashes_type m_num_hashes;

  std::vector<uint8_t> mBloomFilter;

  bool m_blm_frm_mem;

  std::fstream m_bf_stream;

  boost::shared_ptr<lru_cache_using_std<
                      CalcBitIndeces,
                      std::string,boost::shared_ptr<std::vector<uint64_t> >,
                      boost::unordered_map> > m_cache;
  CalcBitIndeces m_calc_bit_indeces;

};
#endif
