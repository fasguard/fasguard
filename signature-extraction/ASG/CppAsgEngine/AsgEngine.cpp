#include <boost/python/module.hpp>
#include <boost/python/def.hpp>
#include <boost/python.hpp>
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <iostream>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include "AsgEngine.h"
#include "Dendrogram.hh"
#include "RegexExtractorLCSS.hh"
#include "SuricataRuleMaker.hpp"

using namespace boost::python;

BOOST_PYTHON_MODULE(asg_engine_ext)
{

  class_<AsgEngine>("AsgEngine", init<dict,bool>())
    .def("setDetectorEventFlags", &AsgEngine::setDetectorEventFlags)
    .def("appendAttack", &AsgEngine::appendAttack)
    .def("appendPacket", &AsgEngine::appendPacket)
    .def("makeTries",&AsgEngine::makeTries)
    .def("makeCandidateSignatureStringSet",
         &AsgEngine::makeCandidateSignatureStringSet)
    ;
}

namespace logging = boost::log;

Ngram:: Ngram(std::string content, unsigned int pkt_offset,
              unsigned int pkt_num):
  m_content(content), m_pkt_offset(pkt_offset), m_pkt_num(pkt_num)
{}

Ngram::~Ngram()
{}

AsgEngine::AsgEngine(dict properties, bool debug_flag) :
  m_properties(properties), m_debug(debug_flag)
{
  std::istringstream(extract<std::string>(properties["ASG.MaxDepth"]))
    >> m_max_depth;
  std::istringstream(extract<std::string>(properties["ASG.MinDepth"]))
    >> m_min_depth;
  m_bloom_filter_dir = extract<std::string>(properties["ASG.BloomFilterDir"]);
  std::string blm_frm_mem =
    extract<std::string>(properties["ASG.BloomFromMemory"]);

  if(blm_frm_mem.compare(std::string("T")) == 0)
    {
      m_blm_frm_mem = true;
    }
  else if(blm_frm_mem.compare(std::string("F")) == 0)
    {
      m_blm_frm_mem = false;
    }
  else
    {
      BOOST_LOG_TRIVIAL(error) << "Bad ASG.BloomFromMemory value: " <<
        blm_frm_mem << std::endl;
      exit(-1);
    }

  BOOST_LOG_TRIVIAL(info) << "ASG.MaxDepth: " << m_max_depth << std::endl;
  BOOST_LOG_TRIVIAL(info) << "ASG.MinDepth: " << m_min_depth << std::endl;
  BOOST_LOG_TRIVIAL(info) << "ASG.BloomFilterDir: " << m_bloom_filter_dir <<
    std::endl;

  if(debug_flag)
    {
      logging::core::get()->set_filter
        (
         logging::trivial::severity >= logging::trivial::debug
         );
      BOOST_LOG_TRIVIAL(info) << "Setting DEBUG" << std::endl;

    }
  else
    {
      logging::core::get()->set_filter
        (
         logging::trivial::severity >= logging::trivial::info
         );
      BOOST_LOG_TRIVIAL(info) << "Setting INFO" << std::endl;

    }
}

AsgEngine::~AsgEngine()
{}

void
AsgEngine::setDetectorEventFlags(bool multiple_attack_flag,
                                 bool attack_boundaries_flag)
{
  m_multiple_attack_flag = multiple_attack_flag;
  m_attack_boundaries_flag = attack_boundaries_flag;
}

void
AsgEngine::appendAttack()
{
  m_detector_report.appendAttack();
}

void
AsgEngine::appendPacket(double time, int service, int sport, int dport,
                    std::string payload, float prob_attack)
{
  m_detector_report.appendPacket(time,service,sport,dport,payload,
                                prob_attack);
}

void
AsgEngine::makeTries()
{
  BOOST_LOG_TRIVIAL(debug) << "Entering makeTries" << std::endl;
  std::cout << "In makeTries" << std::endl;
  std::vector<std::vector<boost::shared_ptr<Packet> > >::const_iterator cit =
    m_detector_report.getAttackStartIterator();
  int cnt = 0;
  while(cit != m_detector_report.getAttackEndIterator())
    {
      BOOST_LOG_TRIVIAL(debug)   << "Attack #" << cnt << std::endl;
      std::vector<boost::shared_ptr<Packet> >::const_iterator pit =
        (*cit).begin();
      // Add attack to trie attack list
      std::vector<boost::shared_ptr<Trie> > cur_attack_vec;
      m_trie_attack_list.push_back(cur_attack_vec);
      int pkt_cnt = 0;
      while(pit != (*cit).end())
        {
          BOOST_LOG_TRIVIAL(debug)   << "Pkt Cnt: " << pkt_cnt << std::endl;

          boost::shared_ptr<AbstractTrieNodeFactory>
            atnf(new MemoryTrieNodeFactory<unsigned char,unsigned int,256>());
          boost::shared_ptr<Trie> st(new Trie(atnf));

          st->insertAllSubstrings((**pit).getPayload().data(),
                                  (**pit).getPayload().size(),m_max_depth);
          cur_attack_vec.push_back(st);
          pit++;
          pkt_cnt++;
        }
      cnt++;
      cit++;
    }
}

void
AsgEngine::makeCandidateSignatureStringSet()
{
  // Based on setting of flags, we process the packets accordingly
  if(m_multiple_attack_flag)
    {
      // Now, we see if the detector has seperated the attacks on its own or not
      if(m_attack_boundaries_flag)
        {
          BOOST_LOG_TRIVIAL(debug)   <<
            "Separated attack code not implemented" << std::endl;

        }
      else
        {
          BOOST_LOG_TRIVIAL(debug)   <<
            "Non-separated attack code not implemented" << std::endl;
          unsupervisedClustering();
        }
    }
  else
    {
          // First, turn each packet into its own trie
          BOOST_LOG_TRIVIAL(debug)   <<
            "In single attack code" << std::endl;
          //makeTries();
          singleAttack();
    }
}

void
AsgEngine::unsupervisedClustering()
{
  std::vector<std::string> pkt_content_list;
  BOOST_LOG_TRIVIAL(debug) << "Entering unsupervisedClustering" << std::endl;

  std::vector<std::vector<boost::shared_ptr<Packet> > >::const_iterator cit =
    m_detector_report.getAttackStartIterator();
  int cnt = 0;
  // We expect only one group of packets containing multiple attacks

  // Currently, we require that all packets in the attack have the same
  // destination port

  int num_pkts = 0;

  std::map<int,int> proto_cnt;
  std::map<int,int> dport_cnt;

  while(cit != m_detector_report.getAttackEndIterator())
    {
      BOOST_LOG_TRIVIAL(debug)   << "Attack #" << cnt << std::endl;
      std::vector<boost::shared_ptr<Packet> >::const_iterator pit =
        (*cit).begin();
      // Add attack to trie attack list
      int pkt_cnt = 0;
      while(pit != (*cit).end())
        {
          BOOST_LOG_TRIVIAL(debug)   << "Pkt Cnt: " << pkt_cnt << std::endl;


          std::string pkt_payload((**pit).getPayload().data(),
                                  (**pit).getPayload().size());

          proto_cnt[(**pit).getProtocol()]++;
          dport_cnt[(**pit).getDstPort()]++;

          pkt_content_list.push_back(pkt_payload);
          pit++;
          pkt_cnt++;
        }
      cnt++;
      cit++;
    }

  // Check that we're only getting data from one protocol and one service
  if((proto_cnt.size() != 1) || (dport_cnt.size() != 1))
    {
      BOOST_LOG_TRIVIAL(error)   << "Need single protocol and port" <<
        std::endl;
      exit(-1);
     }
  int attack_proto = proto_cnt.begin()->first;
  int attack_port = dport_cnt.begin()->first;

  std::string attack_proto_string;

  switch(attack_proto)
    {
    case 1:
      attack_proto_string = "icmp";
      break;
    case 2:
      attack_proto_string = "igmp";
      break;
    case 6:
      attack_proto_string = "tcp";
      break;
    case 17:
      attack_proto_string = "udp";
      break;
    default:
      BOOST_LOG_TRIVIAL(error)   << "Unknown attack protocol: " <<
        attack_proto << std::endl;
      exit(-1);
    }

  std::ostringstream ost;
  ost << attack_port;
  std::string attack_port_string = ost.str();

  // Generate Bloom filter name

  Dendrogram dg(m_properties,pkt_content_list);
  dg.makeDistMtrx();
  boost::shared_ptr<tree<TreeNode> > dgram = dg.makeDendrogram();
  BOOST_LOG_TRIVIAL(debug)   << "After makeDendrogram" << std::endl;
  std::vector<std::set<std::string> > similar_string_sets =
    dg.findDisjointStringSets();
  BOOST_LOG_TRIVIAL(debug)   << "Number of similar string sets " <<
    similar_string_sets.size() << std::endl;

  // Construct Bloom filter name

  ost.str("");

  ost << m_bloom_filter_dir << "/proto_" << attack_proto << "_port_" <<
    attack_port << "_min_" << m_min_depth << "_max_" << m_max_depth <<
    ".bloom";

  std::string bf_name = ost.str();

  BOOST_LOG_TRIVIAL(debug) << "Bloom Filter File Name: "
                           << bf_name << std::endl;

  BloomFilter bf(bf_name,m_blm_frm_mem);

  SuricataRuleMaker srm(attack_proto_string,"any","any","any",
                        attack_port_string);

  int string_set_count = 0;
  for(std::vector<std::set<std::string> >::iterator sset_it =
        similar_string_sets.begin();
      sset_it != similar_string_sets.end();sset_it++)
    {
      BOOST_LOG_TRIVIAL(debug)   << "String Set: "<< string_set_count <<
        ",Size:" << (*sset_it).size() << std::endl;

      if((*sset_it).size() <= 1)
        continue;

      std::vector<std::string> subseq_list =
        dg.gatherSubsequences(*sset_it);
      BOOST_LOG_TRIVIAL(debug)   <<
        "subseq_list Size:" << subseq_list.size() << std::endl;

      RegexExtractorLCSS re(subseq_list);
      std::vector<std::string> regex_pieces =
        re.findMatchSegmentSequence(subseq_list);

      BOOST_LOG_TRIVIAL(debug)   << "Num regex pieces: "<<
        regex_pieces.size() << std::endl;

      std::vector<std::string> filt_regex_pieces =
        filtSigFrags(bf,regex_pieces);

       BOOST_LOG_TRIVIAL(debug)   << "Num filtered regex pieces: "<<
        filt_regex_pieces.size() << std::endl;

       std::vector<std::string>::iterator rp_it = filt_regex_pieces.begin();

       while(rp_it != filt_regex_pieces.end())
         {
           stringstream ss;
           for(int i=0;i<(*rp_it).size();i++)
             {
               ss << std::hex << std::setw(2) <<
                 std::setfill('0') << (unsigned int)((*rp_it)[i]);
               if(i != (*rp_it).size()-1)
                 {
                   ss << " ";
                 }
             }
           BOOST_LOG_TRIVIAL(debug) << ss.str() << endl;
           std::string sig_hex = ss.str();

           std::string snort_rule = srm.makeContentRule(sig_hex);
           BOOST_LOG_TRIVIAL(debug) << snort_rule << endl;

           rp_it++;
         }


      string_set_count++;
    }

}

std::vector<std::string>
AsgEngine::filtSigFrags(BloomFilter &bf,
                        std::vector<std::string> &frag_pieces)
{
  std::vector<std::string> result;

  BOOST_LOG_TRIVIAL(debug)   << "In filtSigFrags, num frag_pieces: " <<
    frag_pieces.size() << std::endl;

  std::vector<std::string>::iterator it = frag_pieces.begin();

  while(it != frag_pieces.end())
    {
      std::set<std::string> ngrams;

      if((*it).size() < m_max_depth)
        {
          it++;
          continue;
        }
      for(int depth=m_min_depth;depth<=m_max_depth;depth++)
        {
          BOOST_LOG_TRIVIAL(debug)   << "Size of frag_piece: " <<
            (*it).size() << std::endl;

          for(int i=0;i<=(*it).size()-depth;i++)
            {
              ngrams.insert((*it).substr(i,depth));
            }
        }
      std::set<std::string>::iterator nit = ngrams.begin();

      bool novel_flag = false;
      while(nit != ngrams.end())
        {
          if(!bf.contains((uint8_t *)((*nit).data()),(*nit).size()))
            {
              novel_flag = true;
              break;
            }
          nit++;
        }
      if(novel_flag)
        {
          result.push_back(*it);
        }
      it++;
    }
  return result;
}

void
AsgEngine::singleAttack()
{
  std::vector<std::string> pkt_content_list;

  BOOST_LOG_TRIVIAL(debug) << "Entering singleAttack" << std::endl;

  std::vector<std::vector<boost::shared_ptr<Packet> > >::const_iterator cit =
    m_detector_report.getAttackStartIterator();

  int cnt = 0;

  // We expect only one group of packets containing a single attack

  // Currently, we require that all packets in the attack have the same
  // destination port

  int num_pkts = 0;

  std::map<int,int> proto_cnt;
  std::map<int,int> dport_cnt;
  while(cit != m_detector_report.getAttackEndIterator())
    {
      BOOST_LOG_TRIVIAL(debug)   << "Attack #" << cnt << std::endl;
      std::vector<boost::shared_ptr<Packet> >::const_iterator pit =
        (*cit).begin();
      // Add attack to trie attack list
      int pkt_cnt = 0;
      while(pit != (*cit).end())
        {
          BOOST_LOG_TRIVIAL(debug)   << "Pkt Cnt: " << pkt_cnt << std::endl;


          BOOST_LOG_TRIVIAL(debug) << "Destination Port: " <<
            (**pit).getDstPort() << std::endl;
          std::string pkt_payload((**pit).getPayload().data(),
                                  (**pit).getPayload().size());

          proto_cnt[(**pit).getProtocol()]++;
          dport_cnt[(**pit).getDstPort()]++;

          pkt_content_list.push_back(pkt_payload);
          pit++;
          pkt_cnt++;
        }
      cnt++;
      cit++;
    }

  // Check that we're only getting data from one protocol and one service
  if((proto_cnt.size() != 1) || (dport_cnt.size() != 1))
    {
      BOOST_LOG_TRIVIAL(error)   << "Need single protocol and port" <<
        std::endl;
      exit(-1);
     }
  int attack_proto = proto_cnt.begin()->first;
  int attack_port = dport_cnt.begin()->first;

  std::string attack_proto_string;

  switch(attack_proto)
    {
    case 1:
      attack_proto_string = "icmp";
      break;
    case 2:
      attack_proto_string = "igmp";
      break;
    case 6:
      attack_proto_string = "tcp";
      break;
    case 17:
      attack_proto_string = "udp";
      break;
    default:
      BOOST_LOG_TRIVIAL(error)   << "Unknown attack protocol: " <<
        attack_proto << std::endl;
      exit(-1);
    }

  std::ostringstream ost;
  ost << attack_port;
  std::string attack_port_string = ost.str();


  // Construct Bloom filter name

  ost.str("");

  ost << m_bloom_filter_dir << "/proto_" << attack_proto << "_port_" <<
    attack_port << "_min_" << m_min_depth << "_max_" << m_max_depth <<
    ".bloom";

  std::string bf_name = ost.str();

  BOOST_LOG_TRIVIAL(debug) << "Bloom Filter File Name: "
                           << bf_name << std::endl;

  BloomFilter bf(bf_name,m_blm_frm_mem);

  SuricataRuleMaker srm(attack_proto_string,"any","any","any",
                        attack_port_string);

  int string_set_count = 0;

  std::vector<Ngram> filt_regex_pieces =
    filtNgrams(bf,pkt_content_list);

  BOOST_LOG_TRIVIAL(debug)   << "Num filtered regex pieces: "<<
    filt_regex_pieces.size() << std::endl;


  std::vector<Ngram>::iterator pc_it = filt_regex_pieces.begin();
  std::set<std::string> seen_already;

  while(pc_it != filt_regex_pieces.end())
    {
      stringstream ss;
      std::string cur_string = (*pc_it).getContent();
      if(seen_already.find(cur_string) != seen_already.end())
        {
          pc_it++;
          continue;
        }
      else if (cur_string.size() < m_min_depth)
        {
          pc_it++;
          continue;
        }
      else
        {
          seen_already.insert(cur_string);
        }
      for(int i=0;i<cur_string.size();i++)
        {
          ss << std::hex << std::setw(2) <<
            std::setfill('0') << (unsigned int)(cur_string[i]);
          if(i != (*pc_it).getContent().size()-1)
            {
              ss << " ";
            }
        }
      BOOST_LOG_TRIVIAL(debug) << ss.str() << endl;
      std::string sig_hex = ss.str();

      std::string snort_rule = srm.makeContentRule(sig_hex);
      BOOST_LOG_TRIVIAL(debug) << snort_rule << endl;

      pc_it++;
    }
}

std::vector<Ngram>
AsgEngine::filtNgrams(BloomFilter &bf,
                      std::vector<std::string> &pkts)
{
  std::set<std::string> ngrams;
  std::vector<Ngram> ngram_result;

  BOOST_LOG_TRIVIAL(debug)   << "In filtNgrams, num pkt content: " <<
    pkts.size() << std::endl;

  std::vector<std::string>::iterator it = pkts.begin();

  unsigned int pkt_num = 1;
  while(it != pkts.end())
    {
      if((*it).size() < m_max_depth)
        {
          it++;
          pkt_num++;
          continue;
        }

      // We collect ngrams for single packets and return only those ngrams
      // whose occurance is a local frequency maximum

      std::vector<Ngram> pkt_ngrams;


      // We take only the shortest string that doesn't get filtered
      int total_ngram = 0;
      int svv_ngram = 0;

      for(int i=0;i<=(*it).size()-m_min_depth;i++)
        {
          int local_max_depth = (i+m_max_depth < (*it).size())?
            m_max_depth:((*it).size()-i);
          for(int depth=m_min_depth;depth<=local_max_depth;depth++)
            {
              std::string ngram = (*it).substr(i,depth);

              if(!bf.contains((uint8_t *)(ngram.data()),ngram.size()))
                {
                  ngrams.insert(ngram);
                  Ngram ngram_obj(ngram,i,pkt_num);
                  pkt_ngrams.push_back(ngram_obj);
                  svv_ngram++;
                  //break;
                }
              total_ngram++;
            }
        }
      BOOST_LOG_TRIVIAL(debug)   << "Total ngram: " <<  total_ngram <<
        " Surviving ngram: " << svv_ngram << std::endl;

      findLocalMaxima(pkt_ngrams,ngram_result,*it,pkt_num);
      it++;
      pkt_num++;
    }


  return ngram_result;
  //return ngrams;
}

void
AsgEngine::findLocalMaxima(std::vector<Ngram> &pkt_ngrams,
                           std::vector<Ngram> &ngram_result,
                           std::string pkt_content,
                           unsigned int pkt_num)
{
  std::vector<unsigned int> histo(pkt_content.size(),0);

  // Make histo of number of ngrams that cover each packet position

  for(std::vector<Ngram>::iterator pkt_ngram_it = pkt_ngrams.begin();
      pkt_ngram_it != pkt_ngrams.end();
      pkt_ngram_it++)
    {
      for(int i = (*pkt_ngram_it).getPktOffset();
          i < (*pkt_ngram_it).getPktOffset() +
            (*pkt_ngram_it).getContent().size();
          i++)
        {
          histo[i] += 1;
        }
    }

  // Now, find and report local maxima

  unsigned int local_max_cnt = 0;
  unsigned int start_run = 0;
  bool in_run = false;

  for(int i=0;i<pkt_content.size();i++)
    {
      if(histo[i] > local_max_cnt)
        {
          local_max_cnt = histo[i];
          start_run = i;
          in_run = true;
          BOOST_LOG_TRIVIAL(debug)   << "Up to: " << local_max_cnt  <<
            " at " << i <<
            std::endl;

        }
      else if(histo[i] < local_max_cnt)
        {
          if(in_run)
            {
              // Make a new entry in ngram_result
              Ngram ngram(pkt_content.substr(start_run,(i-start_run)),
                      i,pkt_num);
              ngram_result.push_back(ngram);
              in_run = false;
            }
          local_max_cnt = histo[i];
          BOOST_LOG_TRIVIAL(debug)   << "Down to: " << local_max_cnt  <<
            " at " << i <<
            std::endl;
          start_run = i;
        }
    }
}
