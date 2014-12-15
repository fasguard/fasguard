#include <boost/log/trivial.hpp>
#include <iostream>
#include "PcapFileEngine.hpp"

namespace fasguard
{
  PcapFileEngine::PcapFileEngine(const std::vector<std::string> pcap_filenames,
                                 bloom_filter &b_filter) :
    m_b_filter(b_filter)
  {
    for (const std::string &p_file : pcap_filenames)
      {
        fillBloom(p_file);
      }
  }

  void PcapFileEngine::fillBloom(std::string pcap_filename)
  {
    BOOST_LOG_TRIVIAL(info) << "Process pcap file: " << pcap_filename
                            << std::endl;

  }

}
