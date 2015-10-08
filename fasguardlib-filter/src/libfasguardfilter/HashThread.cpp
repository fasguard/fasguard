#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/thread/thread.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <fasguardfilter/HashThread.hh>


static boost::atomic<unsigned int> ngram_total;

HashThread::HashThread(boost::lockfree::queue<TrivString,
                       boost::lockfree::fixed_sized<true> > &ngram_q,
                       boost::lockfree::queue<BloomOffsetBlock,
                       boost::lockfree::fixed_sized<true> > &bit_index_q,
                       const CalcBitIndeces &c_bit_i,
                       boost::atomic<bool> &done,
                       boost::atomic<unsigned int> &shutdown_thread_count,
                       unsigned int thread_index) :
  m_ngram_q(ngram_q), m_bit_index_q(bit_index_q), m_calc_bit_indeces(c_bit_i),
  m_done(done),m_shutdown_thread_count(shutdown_thread_count),
  m_thread_index(thread_index)
{
  ngram_total = 0;
    m_cache = boost::shared_ptr<lru_cache_using_std<
                                  CalcBitIndeces,
                                  std::string,
                                  std::vector<uint64_t>,
                                  boost::unordered_map> >(new
                                              lru_cache_using_std<
                                              CalcBitIndeces,
                                              std::string,
                                              std::vector<uint64_t>,
                                              boost::unordered_map>(m_calc_bit_indeces,
                                                                    BloomFilterBase::NUM_CACHE_ENTRIES));
    (*m_cache).setEmptyReturnFlag();
}
void
HashThread::operator()()
{
  // Get ngram off of queue

  TrivString ngram;
  while(!m_done)
    {
      while(m_ngram_q.pop(ngram))
        {
          if((ngram_total % 10000000) == 0)
            {
              BOOST_LOG_TRIVIAL(debug) << "HashThread Ngram TOTAL: " <<
                ngram_total <<
                std::endl;
              BOOST_LOG_TRIVIAL(debug) << "HashThread #" <<
                m_thread_index << " misses: " <<
                (*m_cache).getNumMisses() <<
                " hits: " <<
                (*m_cache).getNumHits() <<
                std::endl;
            }
          ngram_total++;
          std::string ngram_str(ngram.string,ngram.length);
          const std::vector<uint64_t> &results =
            (*m_cache)(ngram_str);

          // If we've seen the string before, it's already in the Bloom filter
          if((*m_cache).getHitFlag())
            {
              continue;
            }

          std::vector<uint64_t>::const_iterator citer = results.begin();
          BloomOffsetBlock bob;
          unsigned int block_cnt = 0;
          while(citer != results.end())
            {
              bob.offsets[block_cnt++] = *citer;
              if(block_cnt == BloomOffsetBlockSize)
                {
                  bob.num_elems = BloomOffsetBlockSize;
                  while(!m_bit_index_q.push(bob))
                    {
                      boost::this_thread::
                        sleep_for(boost::chrono::microseconds(SleepTimeMicroS));
                    }

                  block_cnt = 0;
                }
              citer++;
            }
          if(block_cnt > 0)
            {
              bob.num_elems = block_cnt;
              while(!m_bit_index_q.push(bob))
                {
                  boost::this_thread::
                    sleep_for(boost::chrono::microseconds(SleepTimeMicroS));
                }
            }
        }
      boost::this_thread::sleep_for(boost::chrono::milliseconds(SleepTimeMilS));
    }

BOOST_LOG_TRIVIAL(debug) << "m_done is " <<
  m_done <<
  std::endl;

  // After we're done, finish cleaning things out
  while(m_ngram_q.pop(ngram))
    {
      std::string ngram_str(ngram.string,ngram.length);
      const std::vector<uint64_t> &results =
        (*m_cache)(ngram_str);

      std::vector<uint64_t>::const_iterator iter = results.begin();
      BloomOffsetBlock bob;
      unsigned int block_cnt = 0;

      while(iter != results.end())
        {
          bob.offsets[block_cnt++] = *iter;
          if(block_cnt == BloomOffsetBlockSize)
            {
              while(!m_bit_index_q.push(bob))
                {
                  boost::this_thread::
                    sleep_for(boost::chrono::microseconds(SleepTimeMicroS));
                }
              bob.num_elems = BloomOffsetBlockSize;
              block_cnt = 0;
            }

          iter++;
        }
      if(block_cnt > 0)
        {
          bob.num_elems = block_cnt;
          while(!m_bit_index_q.push(bob))
            {
              boost::this_thread::
                sleep_for(boost::chrono::microseconds(SleepTimeMicroS));
            }
        }

    }

  m_shutdown_thread_count++;
  BOOST_LOG_TRIVIAL(debug) << "Shutting down thread " <<
    m_shutdown_thread_count <<
    std::endl;
}
