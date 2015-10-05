#ifndef BLOOM_INSERT_THREAD_HH
#define BLOOM_INSERT_THREAD_HH
#include <vector>
#include <boost/shared_ptr.hpp>
#include <boost/unordered_map.hpp>
#include <boost/lockfree/queue.hpp>
#include <boost/atomic.hpp>
#include "lru_cache_using_std.h"
#include "BloomFilterBase.hh"
#include "HashThread.hh"

/**
 * A functor class to be handed as a parameter to a thread which turns on
 * bits in the Bloom filter.
 */
class BloomInsertThread
{
public:
  /**
   * A constructor.
   * This constructor takes both the input queue and the output queue for the
   * thread as well as a class that calculates a list of hashed ngram values.
   * @param bit_index_q A reference to a lockfree queue of bit indeces to
   *    turn on in the Bloom filter.
   * @param shutdown_thread_count A counter of number of threads that have
   *    been shut down. The BloomInsertThread can only shutdown when this
   *    is equal to the total number of threads and the bit_index_q has
   *    been emptied.
   * @param total_num_threads - The total number of HashThread threads
   *    started.
   * @param BloomFilter - The Bloom filter that will be added to.
   * @param bitlength - The length of the Bloom filter in bits.
   */
  BloomInsertThread(boost::lockfree::queue<BloomOffsetBlock,
                    boost::lockfree::fixed_sized<true> > &bit_index_q,
                    boost::atomic<unsigned int> &shutdown_thread_count,
                    unsigned int total_num_threads,
                    std::vector<uint8_t> &BloomFilter,
                    uint_fast64_t bitlength,
                    boost::atomic<bool> &bloom_insertion_done);
  /**
   * A function call operator which allows this object to behave as a functor.
   * When invoked, it dequeues items from the bit_index_q and uses them to
   * set bits in the Bloom filter.
   */
  void operator()();
  static const unsigned int SleepTimeMilS = 10;
  static const unsigned int SleepTimeMicroS = 10;

protected:
  boost::lockfree::queue<BloomOffsetBlock, boost::lockfree::fixed_sized<true> >
  &m_bit_index_q;
  boost::atomic<unsigned int> &m_shutdown_thread_count;
  unsigned int m_total_num_threads;
  std::vector<uint8_t> &m_BloomFilter;
  uint_fast64_t m_bitlength;
  boost::atomic<bool> &m_bloom_insertion_done;
};
#endif
