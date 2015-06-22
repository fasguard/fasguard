#include <iostream>
#include "BloomPacketEngine.hpp"
#include "BloomFilter.hh"

using namespace std;

namespace fasguard
{
BloomPacketEngine::BloomPacketEngine(BloomFilter &b_filter,
                                     int min_hor,int max_hor,bool stat_flag) :
  m_bf(b_filter),m_min_hor(min_hor),
  m_max_hor(max_hor),m_stat_flag(stat_flag)
{
  m_opened_backing_file = false;
}
BloomPacketEngine::~BloomPacketEngine()
{}

void
BloomPacketEngine::insertPacket(const unsigned char *str,int lgth)
{
  // Go through entire packet

  //cout << "In insertPacket, string is: '";
  //cout.write((char *)str,lgth);
  //cout << "'" << endl;
  int num_insertions = 0;
  int num_new_insertions = 0;
  if(lgth == 0)
    return;
#if 0
  cout << dec << "Length of pkt: " << lgth << endl;
  for(int j=0;j<lgth;j++)
    {
      cout << hex << (unsigned int)str[j];
    }
  cout << endl;
#endif
  const unsigned char *end_str = str + lgth;

  register const unsigned char *cur = str;

  while(cur < end_str)
    {
      int cur_max_lgth = ((end_str - cur + 1) > m_max_hor)?
        m_max_hor:(end_str - cur);
      for(register int i=m_min_hor;i<=cur_max_lgth;i++)
        {
          if(m_stat_flag)
            {
              //std::cout << "Before contains" << std::endl;
              if(!m_bf.contains(cur,i))
                {
                  m_bf.insert(cur,i);
                  num_new_insertions++;
                }
              num_insertions++;
            }
          else
            {
              m_bf.insert(cur,i);
            }
        }
      cur++;
    }
  if(m_stat_flag)
    {
      cout << dec << num_new_insertions << " new insertions out of "
           << num_insertions << endl;
    }
}

  bool BloomPacketEngine::flush(const std::string &filename)
{
  return m_bf.flush(filename);
}
}
