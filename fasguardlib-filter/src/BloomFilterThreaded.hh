#ifndef BLOOM_FILTER_THREADED_HH
#define BLOOM_FILTER_THREADED_HH
#include <vector>
#include <fstream>
#include <boost/shared_ptr.hpp>
#include <boost/unordered_map.hpp>
#include "lru_cache_using_std.h"
#include <boost/thread/thread.hpp>
#include <boost/lockfree/queue.hpp>
#include "BloomFilterBase.hh"
#include "HashThread.hh"

std::vector<HashThread> ht_vec;

//boost::shared_ptr<std::vector<uint64_t> >
//calcBitIndeces(std::string ngram);
/**
 * @brief Implementation of Bloom filter for ngrams.
 *
 * This stores a Bloom filter for a range of ngram sizes from the payload of
 * large numbers of packets for a single TCP or UDP service.
 */
class BloomFilterThreaded : public BloomFilterBase
{
public:
  /**
   * Constructor. This accepts parameters that specify the benign traffic
   * to be stored in the Bloom filter as well as parameters for the sizing of
   * the Bloom filter. This constructor is used for the initial construction
   * of a BloomFilterThreaded object, not restoring a BloomFilterThreaded object from
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
  BloomFilterThreaded(size_t inserted_items, double probability_false_positive,
              int ip_protocol_num, int port_num, int min_ngram_size,
                      int max_ngram_size,int thread_num);
  /**
   * Constructor for restoring Bloom filter from persistent store.
   * @param filename Name of file containing persistent Bloom filter.
   * @param from_mem_p If true, Bloom filter data is loaded in memory. If
   *    false, file is accesed for each Bloom filter bit using fseek.
   */
  BloomFilterThreaded(const std::string &filename,bool from_mem_p);
  /**
   * Destructor.
   */
  ~BloomFilterThreaded();
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

  /**
   * Writes out a Bloom filter that is a combination of the current BloomFilterThreaded
   * and a BloomFilterThreaded given as a first argument.
   * @param other Other Bloom filter to combine with.
   * @param output_file Filename into which result Bloom Filter will be written.
   */
  void WriteCombined(BloomFilterThreaded &other,std::string output_file);

  void signalDone()
  {
    m_ngram_done = true;
  }

  void threadsCompleted()
  {
    while(m_shutdown_thread_count < m_thread_num)
      {
        boost::this_thread::sleep_for(boost::chrono::milliseconds(HashThread::SleepTimeMilS));
      }
  }

  bool bloomInsertionDone()
  {
    return m_bloom_insertion_done;
  }
  static const unsigned int MAX_HASHES = 512;
  static const unsigned int CHAR_SIZE_BITS = 8;
  static const uint32_t HeaderLengthInBytes = 4096;
  static const unsigned int NUM_CACHE_ENTRIES = 200000;
  static const unsigned int NgramQueueLength = 65534;
  static const unsigned int BloomFilterThreadedOffsetQueueLength = 65534;
  //static const unsigned int NumThreads = 2;

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

  std::vector<boost::shared_ptr<HashThread> > m_thread_list;
  boost::thread_group m_ngram_hashers;
  boost::thread_group m_bloom_insert;
  boost::atomic<bool> m_ngram_done;
  boost::atomic<unsigned int> m_shutdown_thread_count;
  boost::atomic<bool> m_bloom_insertion_done;
  int m_thread_num;
   // Queue of ngrams to process

  // Queue of vectors of Bloom filter offsets

  //boost::lockfree::queue<uint64_t>
  //m_bfilt_offset_q(128);

};


#endif
