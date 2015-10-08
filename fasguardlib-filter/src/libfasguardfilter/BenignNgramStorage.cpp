#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <boost/log/trivial.hpp>
#include <sstream>
#include <fasguardfilter/BenignNgramStorage.hh>

extern "C" void
fasguardfilter()
{
    // no-op
}

BenignNgramStorage::BenignNgramStorage(int ip_protocol_num, int port_num,
                                       int min_ngram_size, int max_ngram_size):
  m_ip_protocol_num(ip_protocol_num), m_port_num(port_num),
  m_min_ngram_size(min_ngram_size),m_max_ngram_size(max_ngram_size),
  m_insertions(0),m_unique_insertions(0)
{}

void
BenignNgramStorage::loadParams(const std::map<std::string,std::string>
                               &properties)
{
  std::map<std::string,std::string>::const_iterator cit =
    properties.begin();

  while(cit != properties.end())
    {
      if((cit->first).compare(std::string("IP_PROTOCOL_NUMBER")) == 0)
          {
            std::istringstream(cit->second) >> m_ip_protocol_num;
          }
      else if((cit->first).compare(std::string("TCP_IP_PORT_NUM")) == 0)
          {
            std::istringstream(cit->second) >> m_port_num;
          }
      else if((cit->first).compare(std::string("MIN_NGRAM_SIZE")) == 0)
          {
            std::istringstream(cit->second) >> m_min_ngram_size;
          }
      else if((cit->first).compare(std::string("MAX_NGRAM_SIZE")) == 0)
        {
          std::istringstream(cit->second) >> m_max_ngram_size;
        }
      else if((cit->first).compare(std::string("NUM_PAYLOAD_BYTES_PROCESSED"))
              == 0)
        {
          std::istringstream(cit->second) >> m_bytes_processed;
        }
      else
        {
          BOOST_LOG_TRIVIAL(error) << "Unknown property: " <<
            cit->first << std::endl;
        }
      cit++;
    }
}


BenignNgramStorage::~BenignNgramStorage()
{}

void
BenignNgramStorage::setNumBytesProcessed(unsigned long long int
                                         num_bytes_processed)
{
  m_bytes_processed = num_bytes_processed;
}

bool
BenignNgramStorage::Compare(const BenignNgramStorage &other)
{
  return (m_ip_protocol_num == other.m_ip_protocol_num) &&
    (m_port_num == other.m_port_num) &&
    (m_min_ngram_size == other.m_min_ngram_size) &&
    (m_max_ngram_size == other.m_max_ngram_size);
}
