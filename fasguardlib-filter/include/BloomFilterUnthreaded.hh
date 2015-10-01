#ifndef BLOOM_FILTER_UNTHREADED_HH
#define BLOOM_FILTER_UNTHREADED_HH
#include <vector>
#include <fstream>
#include <boost/shared_ptr.hpp>
#include <boost/unordered_map.hpp>
#include <lru_cache_using_std.h>
#include <BenignNgramStorage.hh>
#include <BloomFilterBase.hh>

/**
 * @brief Implementation of Bloom filter for ngrams.
 *
 * This stores a Bloom filter for a range of ngram sizes from the payload of
 * large numbers of packets for a single TCP or UDP service.
 */
class BloomFilterUnthreaded : public BloomFilterBase
{
public:
  /**
   * Constructor. This accepts parameters that specify the benign traffic
   * to be stored in the Bloom filter as well as parameters for the sizing of
   * the Bloom filter. This constructor is used for the initial construction
   * of a BloomFilterUnthreaded object, not restoring a BloomFilterUnthreaded object from
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
  BloomFilterUnthreaded(size_t inserted_items, double probability_false_positive,
              int ip_protocol_num, int port_num, int min_ngram_size,
              int max_ngram_size);
  /**
   * Constructor for restoring Bloom filter from persistent store.
   * @param filename Name of file containing persistent Bloom filter.
   * @param from_mem_p If true, Bloom filter data is loaded in memory. If
   *    false, file is accesed for each Bloom filter bit using fseek.
   */
  BloomFilterUnthreaded(const std::string &filename,bool from_mem_p);
  /**
   * Destructor.
   */
  ~BloomFilterUnthreaded();
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
  //virtual bool flush(std::string filename);

  /**
   * Returns the first value in the Bloom filter that's above the input value.
   * Used only for testing.
   * @param val Input value to compare to.
   * @return First value above val.
   */
  unsigned int entryAbove(unsigned int val);

  static const unsigned int MAX_HASHES = 512;
  static const unsigned int CHAR_SIZE_BITS = 8;
  static const uint32_t HeaderLengthInBytes = 4096;
  static const unsigned int NUM_CACHE_ENTRIES = 100000;

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

  // boost::shared_ptr<lru_cache_using_std<
  //                  CalcBitIndeces,
  //                  std::string,std::vector<uint64_t>,
  //                  boost::unordered_map> > m_cache;
  CalcBitIndeces m_calc_bit_indeces;

};
#endif
