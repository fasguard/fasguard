#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <boost/log/trivial.hpp>
#include <iostream>
#include <boost/thread/thread.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include "PcapFileEngine.hpp"
#include "BloomPacketEngine.hpp"

namespace fasguard
{
  PcapFileEngine::PcapFileEngine(const std::vector<std::string> pcap_filenames,
                                 BloomFilterBase &b_filter,int min_depth,
                                 int max_depth) :
    m_b_filter(b_filter),m_b_pkt_eng(b_filter,min_depth,max_depth,false),
    m_bytes_processed(0)
  {
    for (const std::string &p_file : pcap_filenames)
      {
        fillBloom(p_file);
      }
    BOOST_LOG_TRIVIAL(debug) << "Finished input packets " <<
      std::endl;

    m_b_filter.signalDone();

    // Wait for bloom insertion to complete

    while(!b_filter.bloomInsertionDone())
      {
        boost::this_thread::sleep_for(boost::chrono::milliseconds(SleepTimeMilS));

      }

    // Record number of bytes inserted into Bloom Filter

    m_b_filter.setNumBytesProcessed(m_bytes_processed);
  }

  void PcapFileEngine::fillBloom(std::string pcap_filename)
  {
    BOOST_LOG_TRIVIAL(info) << "Process pcap file: " << pcap_filename
                            << std::endl;
    processFile(pcap_filename);
  }

bool
PcapFileEngine::processFile(const std::string& filename)
{

  pcap_t* p = NULL;

  if(false == initPcap(p, filename))
  {
    return(false);
  }

  assert(p != NULL);

  if(pcap_datalink(p) != DLT_EN10MB)
  {
    BOOST_LOG_TRIVIAL(error) << "Error: Unsupported data-link protocol: " <<
      getDataLinkInfo(p) << std::endl;


    // close the descriptor and NULLify the pointer
    closePcap(p);

    return(false);
  }

  unsigned int next_report_bytes = BytesProcessedDelta;
  // now let's process all packets
  do
  {
    // pointer to layer-4 payload
    const u_char* payload = NULL;

    // layer-4 payload length
    size_t payload_len = 0;

    // get the next packet from Pcap
    int rv = getNextPacket(p, payload, payload_len);
    // BOOST_LOG_TRIVIAL(debug) << "Got next packet, rv = " <<
    //   rv << std::endl;

    static unsigned int num_pkts = 0;

    num_pkts++;


    // timeouts are not possible in this application
    assert(rv != 0);

    // problem retrieving the packet
    if(-1 == rv)
    {
      continue;
    }

    // problem parsing the packet
    if(-3 == rv)
    {
      continue;
    }

    // no more packets
    if(-2 == rv)
    {
      break;
    }

    // packet read successfully
    assert(1 == rv);

    // insert all substrings up to the given depth into the Bloom filter
    // BOOST_LOG_TRIVIAL(debug) << "before insertPacket" << std::endl;

    m_b_pkt_eng.insertPacket(reinterpret_cast<const unsigned char*>(payload),
                     payload_len);

    // accumulate bytes_processed with the length of the current payload
    m_bytes_processed += payload_len;
    if(m_bytes_processed > next_report_bytes)
      {
        BOOST_LOG_TRIVIAL(info)
          << "Bytes Processed: " << m_bytes_processed << std::endl;
        next_report_bytes += BytesProcessedDelta;
      }

  } while(true);

  closePcap(p);
  BOOST_LOG_TRIVIAL(info)
    << "Finsished processing: " << filename << std::endl;

  return(true);
}

/**
 * Fully initialize pcap for the given dump file
 *
 * @param p Pointer to Pcap descriptor
 *
 * @param dump Name of Pcap dump file to process
 *
 * @return 'true' if Pcap fully initialized successfully, 'false' otherwise
 */

  bool
  PcapFileEngine::initPcap(pcap_t*& p, const std::string&  dump)
{
  // p != 0 means that the descriptor was already initialized
  assert(NULL == p);

  // Pcap uses this to store error messages. The PCAP_ERRBUF_SIZE is somewhere
  // defined by the pcap library
  char errbuf[PCAP_ERRBUF_SIZE];

  BOOST_LOG_TRIVIAL(debug)
    << "Opening pcap savefile: " << dump << std::endl;

  // open the dump file
  p = pcap_open_offline(dump.c_str(),
                        errbuf);

  // pcap_open_offline will return NULL on failure
  if(NULL == p)
  {
    // notice how we use the 'errbuf' to show what happened
    BOOST_LOG_TRIVIAL(error) <<
      "Error: Unable to open Pcap dump file \"" << dump << "\": "
                             << errbuf << std::endl;

    return(false);
  }

  return(true);
}

  std::string
  PcapFileEngine::getDataLinkInfo(pcap_t* p)
  {
    assert(p != NULL);

    int dlt = pcap_datalink(p);

    const char* dlt_name_tmp = pcap_datalink_val_to_name(dlt);

    std::string dlt_name = (NULL != dlt_name_tmp) ? std::string("DLT_") + dlt_name_tmp : "UNKNOWN";

    const char* dlt_desc_tmp = pcap_datalink_val_to_description(dlt);

    std::string dlt_desc = (NULL != dlt_desc_tmp) ? dlt_desc_tmp : "UNKNOWN";

    return(dlt_name + " (" + dlt_desc + ")");
  }

/**
 * Close the Pcap descriptor
 *
 * NOTE: The provided pointer to the Pcap descriptor will always be NULL
 * when this function returns
 *
 * NOTE: If the descriptor is already closed, this function has no effect
 *
 * @param p Pointer to Pcap descriptor
 */

void
PcapFileEngine::closePcap(pcap_t*& p)
{
  // if the descriptor is already closed, return immediately
  if(NULL == p)
  {
    return;
  }

  // close the descriptor and NULLify the pointer
  pcap_close(p);
  p = NULL;
}

/**
 * Get the next packet available from a Pcap descriptor
 *
 * @param p Pointer to open Pcap descriptor
 *
 * @param payload Pointer to layer-4 payload of next packet (output)
 *
 * @param payload_len Length of layer-4 payload of next packet (output)
 *
 * @return 1 if the packet read and parsed successfully, 0 if a timeout
 *  occurred (this should never happen!), -1 if an error occurred in getting
 *  the packet from Pcap, -2 if there are no more packets to be read, or -3 if
 *  there was an error parsing the packet
 */

int
PcapFileEngine::getNextPacket(
        pcap_t*         p,
  const u_char*&        payload,
        size_t&   payload_len)
{
  payload = NULL;
  payload_len = 0;

  // 'p' must point to an open Pcap descriptor
  assert(p != NULL);

  // Pcap pachet header
  struct pcap_pkthdr pkthdr;

  // Pointer to Ethernet frame
  const u_char* pkt = NULL;

#ifndef WITHOUT_PCAP_NEXT_EX
  // temporary pointer to the Pcap header for the next packet
  struct pcap_pkthdr* tmp_pkthdr = NULL;

  // try to get the next packet
  int rv = pcap_next_ex(p, &tmp_pkthdr, &pkt);

  // no more packets available
  if(-2 == rv)
  {
    return(-2);
  }

  // an error occurred reading from Pcap
  if(-1 == rv)
  {
    return(-1);
  }

  // a timeout occurred reading from Pcap
  // NOTE: This will never happen when reading from Pcap dump file!
  if(0 == rv)
  {
    return(0);
  }

  // these better be pointing to something!
  assert(pkt != NULL);
  assert(tmp_pkthdr != NULL);

  // make a copy of the temporary packet header
  pkthdr = *tmp_pkthdr;

#else

  // get the next packet from Pcap
  pkt = pcap_next(p, &pkthdr);

  // if pcap_next() returns NULL, we must assume it is because there are
  // no more packets available
  if(NULL == pkt)
  {
    return(-2);
  }

#endif

  // extract the payload and payload length
  // NOTE: payload_len is a reference provided by our caller
  // NOTE: payload is a reference provided by our caller
  if(false == extractPayload(pkt, pkthdr.caplen, payload, payload_len))
  {
    return(-3);
  }

  // success!
  return(1);
}

/**
 * Extract the payload and payload length from a packet captured from Pcap
 *
 * NOTE: This function only supports TCP and UDP packets
 *
 * NOTE: This function does no checking to determine if the layer-4 protocol
 * and destination port are what the use provided. It is assumed that the Pcap
 * capture filter has been successfully applied so as to only allow appropriate
 * packets to be captured.
 *
 * @param pkt Pointer to captured packet
 *
 * @param caplen Length of captured packet
 *
 * @param payload Pointer to layer-4 payload (output)
 *
 * @param payload_len Length of layer-4 payload (output)
 *
 * @return 'true' if the payload and payload length successfully extracted,
 *  'false' otherwise
 */

bool
PcapFileEngine::extractPayload(
  const u_char*  pkt,
        size_t   caplen,
  const u_char*& payload,
        size_t&  payload_len)
{
  // give the payload and payload length a default value, just to be neat
  payload = NULL;
  payload_len = 0;

  // it better not be NULL!
  assert(pkt != NULL);

  // temporary storage
  uint8_t  tmp8  = 0;
  uint16_t tmp16 = 0;

  // we need to determine the layer-3 protocol from the Ethernet header
  tmp16 = 0;
  std::copy(pkt + 2*ETHER_ADDR_LEN, pkt + 2*ETHER_ADDR_LEN + 2,
            reinterpret_cast<u_char*>(&tmp16));
  uint16_t l3_proto = ntohs(tmp16);

  // if the layer-3 protocol is not IP, we need to go to the next packet
  if(l3_proto != ETHERTYPE_IP && l3_proto != ETHERTYPE_VLAN)
  {
    BOOST_LOG_TRIVIAL(error) << "Warning: not ETHERTYPE_IP or ETHERTYPE_VLAN "
                             << std::hex << l3_proto << std::dec << std::endl;
    return(false);
  }

  // for convnience, we'll create a pointer to the start of the IP packet
  const u_char* ip_pkt;
  if(l3_proto == ETHERTYPE_IP)
    {
      ip_pkt = pkt + 2*ETHER_ADDR_LEN + 2;
    }
  else
    {
      std::copy(pkt + 2*ETHER_ADDR_LEN+4, pkt + 2*ETHER_ADDR_LEN + 8,
            reinterpret_cast<u_char*>(&tmp16));
      l3_proto = ntohs(tmp16);

      if(l3_proto != ETHERTYPE_IP)
        {
          BOOST_LOG_TRIVIAL(error) << "Warning: not ETHERTYPE_IP "
                             << std::hex << l3_proto << std::dec << std::endl;
          return(false);
        }
      ip_pkt = pkt + 2*ETHER_ADDR_LEN + 6;
    }

  // now we'll read out the IP header length and version
  uint8_t ip_vhl = 0;
  std::copy(ip_pkt, ip_pkt + 1, reinterpret_cast<u_char*>(&ip_vhl));

  // TODO: I'm not sure which is more prudent to check for first:
  // IP version vs Header length

  // extract the version number
  uint8_t ip_version = (ip_vhl & 0xf0) >> 4;

  // if it's not IPv4, go to the next packet
  if(ip_version != 4)
  {
    BOOST_LOG_TRIVIAL(error) << "Warning: Unsupported IP version: "
         << static_cast<unsigned int>(ip_version) << std::endl;

    return(false);
  }

  // get the header length (word length)
  uint8_t ip_hlen = ip_vhl & 0x0f;

  // IPv4 header must be at least 20 bytes (5 words)
  if(ip_hlen < 5)
  {
    BOOST_LOG_TRIVIAL(error) << "Warning: IP packet is truncated." << std::endl;

    return(false);
  }

  // now we extract the total length, which is the total number of bytes
  // in the IPv4 header and payload
  tmp16 = 0;
  std::copy(ip_pkt + 2, ip_pkt + 2 + 2, reinterpret_cast<u_char*>(&tmp16));
  uint16_t total_len = ntohs(tmp16);

  // if we captured less than the entire length of the packet, go to the
  // next packet
  if(caplen < total_len)
  {
    BOOST_LOG_TRIVIAL(error) << "Warning: Capture length is less than the packet length." << std::endl;

    return(false);
  }

  // if the IPv4 datagram is fragmented, skip
  if(1 == (((*(ip_pkt + 6)) & 0x20) >> 5))
  {
    BOOST_LOG_TRIVIAL(error) << "Datagram fragmented" << std::endl;
    return(false);
  }

  // extract the flags and fragment offset
  tmp16 = 0;
  std::copy(ip_pkt + 6, ip_pkt + 6 + 2, reinterpret_cast<u_char*>(&tmp16));

  // if this is the last fragment in a fragmented IPv4 packet, we must also
  // skip it
  // NOTE: We don't have to use ntohs() the outer result here because we're
  // comparing with 0, which is the same in either order
  // NOTE: If the capture filter requires information from the layer-4 header,
  // this expression shouldn't ever evaluate to 'true'
  if(0 != (tmp16 & htons(0x1FFF)))
  {
     BOOST_LOG_TRIVIAL(error) << "Last fragment" << std::endl;
    return(false);
  }

  // Get the layer-4 protocol. It's a single byte, so we don't worry about
  // byte ordering
  unsigned int l4_proto = 0;
  std::copy(ip_pkt + 9, ip_pkt + 10, reinterpret_cast<u_char*>(&l4_proto));

  // for convenience, let's create a pointer to the start of the layer-4 packet
  const u_char* l4_pkt = ip_pkt + (ip_hlen * 4);

  // the initial value represents the length of the start of the layer 4
  // headers to the end of the packet. We'll subtract off the length of
  // the layer 4 headers next
  payload_len = total_len - (ip_hlen * 4);

  // handle UDP and TCP separately
  switch(l4_proto)
  {
    case IPPROTO_UDP: // udp
    {
      // for convenience, we'll create a pointer to the UDP packet
      const u_char* udp_pkt = l4_pkt;

#ifndef NDEBUG
      // grab the UDP length for a sanity check
      tmp16 = 0;
      std::copy(udp_pkt + 4, udp_pkt + 4 + 2, reinterpret_cast<u_char*>(&tmp16));
      uint16_t udp_len = ntohs(tmp16);

      // we haven't subtracted the UDP header length from payload_len yet, so
      // these better be equal!
      assert(udp_len == payload_len);
#endif

      // payload starts 8 bytes after the start of the UDP header
      payload = udp_pkt + 8;

      // UDP headers are always 8 bytes
      payload_len -= 8;

      break;
    }
    case IPPROTO_TCP: // tcp
    {
      // for convenience, we'll create a pointer to the TCP packet
      const u_char* tcp_pkt = l4_pkt;

      // extract the TCP header length (word length)
      tmp8 = 0;
      std::copy(tcp_pkt + 12, tcp_pkt + 12 + 1, reinterpret_cast<u_char*>(&tmp8));
      tmp8 = (tmp8 >> 4) & 0x0f;
      uint8_t tcp_hlen = tmp8;

      // the TCP header must be at least 20 bytes (5 words)
      if(tcp_hlen < 5)
      {
        BOOST_LOG_TRIVIAL(error) << "Warning: TCP packet is truncated." << std::endl;

        return(false);
      }

      // mark the start of the TCP payload
      payload = tcp_pkt + (tcp_hlen * 4);

      // The TCP header tells you how long it is
      payload_len -= (tcp_hlen * 4);

      break;
    }
    default: // not TCP or UDP
    {
      BOOST_LOG_TRIVIAL(error) << "Not TCP or UDP" << std::endl;
      return(false);
    }
  }

  // just a quick sanity check
  assert(payload != NULL);

  return(true);
}

}
