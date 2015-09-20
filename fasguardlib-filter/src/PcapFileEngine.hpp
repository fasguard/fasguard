#ifndef PCAPFILEENGINE_HPP
#define PCAPFILEENGINE_HPP
#include <vector>
#include <string>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>

#include "BloomFilterBase.hh"
#include "BloomPacketEngine.hpp"

namespace fasguard
{
  /**
   * @brief Class for going through multiple pcap files and building up a Bloom
   *    filter.
   * @note All input pcap files are expected to be for the same port.
   */
  class PcapFileEngine
  {
  public:
    /**
     * @brief Constuctor.
     *
     * @param[in] pcap_filenames A vector of strings containing the names of
     *          the pcap files.
     * @param[in] bloom_filter Bloom filter into which the ngrams from the
     *          packets are placed.
     */
    PcapFileEngine(const std::vector<std::string> pcap_filenames,
                   BloomFilterBase &b_filter,int min_depth,
                   int max_depth);
    static const int BytesProcessedDelta = 100000;
    static const unsigned int SleepTimeMilS = 10;

  protected:
    void fillBloom(std::string pcap_filename);
    bool processFile(const std::string& filename);
    bool initPcap(pcap_t*& p,const std::string&  dump);
    std::string getDataLinkInfo(pcap_t* p);
    int getNextPacket(pcap_t* p, const u_char*& payload, size_t& payload_len);
    void closePcap(pcap_t*& p);
    bool extractPayload(const u_char*  pkt, size_t   caplen,
                        const u_char*& payload, size_t&  payload_len);
    BloomFilterBase &m_b_filter;
    BloomPacketEngine m_b_pkt_eng;
    unsigned long long int m_bytes_processed;
  };
}

#endif
