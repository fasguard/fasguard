#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/thread/thread.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include "BloomInsertThread.hh"

BloomInsertThread::BloomInsertThread(boost::lockfree::queue<BloomOffsetBlock,
                                     boost::lockfree::fixed_sized<true> >
                                     &bit_index_q,
                                     boost::atomic<unsigned int>
                                     &shutdown_thread_count,
                                     unsigned int total_num_threads,
                                     std::vector<uint8_t> &BloomFilter,
                                     uint_fast64_t bitlength,
                                     boost::atomic<bool> &bloom_insertion_done):
  m_bit_index_q(bit_index_q),m_shutdown_thread_count(shutdown_thread_count),
  m_total_num_threads(total_num_threads),m_BloomFilter(BloomFilter),
  m_bitlength(bitlength),m_bloom_insertion_done(bloom_insertion_done)
{}

static unsigned int ngram_cnt = 0;
void
BloomInsertThread::operator()()
{
  for(int i=0;i<BloomFilterBase::CHAR_SIZE_BITS;i++)
    {
      BOOST_LOG_TRIVIAL(debug) << "BloomFilterBase::BIT_MASK["
                              << i << "]=" <<
        BloomFilterBase::BIT_MASK[i % BloomFilterBase::CHAR_SIZE_BITS]
                              << std::endl;
    }

  BloomOffsetBlock bob;

  while(m_shutdown_thread_count < m_total_num_threads)
    {
      //uint64_t bit_index;
      //while(m_bit_index_q.pop(bit_index))
      while(m_bit_index_q.pop(bob))
        {
          for(int i=0;i<bob.num_elems;i++)
            {
              uint64_t bit_index = bob.offsets[i];
              if((bit_index / BloomFilterBase::CHAR_SIZE_BITS) >=
                 m_BloomFilter.size())
                {
                  BOOST_LOG_TRIVIAL(error) << "Bad index " <<
                    bit_index << (bit_index / BloomFilterBase::CHAR_SIZE_BITS)
                                           << " greater than size "
                                           << m_BloomFilter.size() << std::endl;
                  exit(-1);
                }
              // BOOST_LOG_TRIVAL(debug) << "Sizeof BloomFilterBase::BIT_MASK: "
              //                          << sizeof(BloomFilterBase::BIT_MASK)
              //                          << std::endl;
              m_BloomFilter[bit_index / BloomFilterBase::CHAR_SIZE_BITS] |=
                BloomFilterBase::BIT_MASK[bit_index %
                                          BloomFilterBase::CHAR_SIZE_BITS];
              ngram_cnt++;

              if((ngram_cnt % 10000000) == 0)
                {
                  BOOST_LOG_TRIVIAL(debug) << "Num ngram inserts: " <<
                    ngram_cnt << std::endl;
                }
            }
        }
      //boost::this_thread::sleep_for(boost::chrono::milliseconds(SleepTimeMilS));
      boost::this_thread::sleep_for(boost::chrono::microseconds(SleepTimeMicroS));

    }

  // Cleanup after all threads shutdown

  uint64_t bit_index;

  while(m_bit_index_q.pop(bob))
    {
      for(int i=0;i<bob.num_elems;i++)
        {
          uint64_t bit_index = bob.offsets[i];
          if((bit_index / BloomFilterBase::CHAR_SIZE_BITS) >=
             m_BloomFilter.size())
            {
              BOOST_LOG_TRIVIAL(error) << "Bad index " <<
                bit_index << (bit_index / BloomFilterBase::CHAR_SIZE_BITS) <<
                " greater than size " << m_BloomFilter.size() << std::endl;
              exit(-1);
            }
          m_BloomFilter[bit_index / BloomFilterBase::CHAR_SIZE_BITS] |=
            BloomFilterBase::BIT_MASK[bit_index %
                                      BloomFilterBase::CHAR_SIZE_BITS];
        }
    }
  m_bloom_insertion_done = true;
}
