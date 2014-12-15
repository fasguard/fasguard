#ifndef PCAPFILEENGINE_HPP
#define PCAPFILEENGINE_HPP
#include <vector>
#include <string>
#include <pcap.h>

#include "bloomfilter.hpp"

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
                   bloom_filter &b_filter);
  protected:
    void fillBloom(std::string pcap_filename);
    bloom_filter &m_b_filter;

  };
}

#endif
