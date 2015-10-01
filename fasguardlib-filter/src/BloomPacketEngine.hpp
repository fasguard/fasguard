#ifndef BLOOM_PACKET_ENGINE_HH
#define BLOOM_PACKET_ENGINE_HH

#include <string>
#include "BloomFilter.hh"

namespace fasguard
{
  class BloomPacketEngine
  {
  public:
    BloomPacketEngine(BloomFilter &b_filter,
                      int min_hor,int max_hor,bool stat_flag=true);
    ~BloomPacketEngine();
    void insertPacket(const unsigned char *str,int lgth);
    bool flush(const std::string &filename);
  private:
    BloomFilter &m_bf;
    int m_min_hor;
    int m_max_hor;
    bool m_stat_flag;
    bool m_opened_backing_file;
  };
}
#endif
