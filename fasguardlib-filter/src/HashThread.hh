#ifndef HASH_THREAD_HH
#define HASH_THREAD_HH
#include <vector>
#include <boost/shared_ptr.hpp>
#include <boost/unordered_map.hpp>
#include <boost/lockfree/queue.hpp>
#include <boost/atomic.hpp>
#include "lru_cache_using_std.h"
#include "BloomFilterBase.hh"

static const unsigned int MaxNgramLength = 16;
static const unsigned int TrivStringBlockSize = 100;
static const unsigned int BloomOffsetBlockSize = 24;

/**
 * Structure to hold strings. Needs a trivial destructor to be placed on
 * lockfree queue.
 */
struct triv_string
{
  unsigned int length;
  char string[MaxNgramLength];
};

typedef struct triv_string TrivString;

class HashThread;

struct triv_string_block
{
  unsigned int num_items;
  TrivString elements[TrivStringBlockSize];
};

typedef struct triv_string_block TrivStringBlock;

struct bloom_offset_block
{
  unsigned int num_elems;
  uint64_t offsets[BloomOffsetBlockSize];
};

typedef struct bloom_offset_block BloomOffsetBlock;

/**
 * A functor class to be handed as a paramter to each thread.
 **/
class HashThread
{
public:
  /**
   * A constructor.
   * This constructor takes both the input queue and the output queue for the
   * thread as well as a class that calculates a list of hashed ngram values.
   * @param ngram_q A reference to a lockfree queue of ngrams to be processed.
   * @param bit_index_q A reference to a lockfree queue of bit indeces to
   *    turn on in the Bloom filter.
   * @param c_bit_i A reference to a CalcBitIndeces object which takes an
   *    ngram and calculates a set of 64-bit hashes to be used as bit
   *    indeces.
   * @param ngram_done A semaphore flag to inform threads that all processing is
   *    done and to shut down. This indicates that all ngrams have been put
   *    on the ngram queue
   * @param shutdown_thread_count A counter of number of threads that have
   *    been shut down. The BloomInsertThread can only shutdown when this
   *    is equal to the total number of threads and the bit_index_q has
   *    been emptied.
   */
  HashThread(boost::lockfree::queue<TrivString,
             boost::lockfree::fixed_sized<true> > &ngram_q,
             boost::lockfree::queue<BloomOffsetBlock,
             boost::lockfree::fixed_sized<true> > &bit_index_q,
             const CalcBitIndeces &c_bit_i,
             boost::atomic<bool> &ngram_done,
             boost::atomic<unsigned int> &shutdown_thread_count,
             unsigned int thread_index);
  /**
   * A function call operator which allows this object to behave as a functor.
   * When invoked, it uses the CalcBitIndeces object to calculate a vector
   * of bit indices which are then enqueued on the m_bit_index_q queue.
   */
  void operator()();

  static const unsigned int SleepTimeMilS = 10;
  static const unsigned int SleepTimeMicroS = 1;

protected:
  boost::shared_ptr<lru_cache_using_std<
                      CalcBitIndeces,
                      std::string,std::vector<uint64_t>,
                      boost::unordered_map> > m_cache;
  boost::lockfree::queue<TrivString, boost::lockfree::fixed_sized<true> > &m_ngram_q;
  boost::lockfree::queue<BloomOffsetBlock,
                         boost::lockfree::fixed_sized<true> > &m_bit_index_q;
  const CalcBitIndeces &m_calc_bit_indeces;
  boost::atomic<bool> &m_done;
  boost::atomic<unsigned int> &m_shutdown_thread_count;
  unsigned int m_thread_index;
};

#endif
