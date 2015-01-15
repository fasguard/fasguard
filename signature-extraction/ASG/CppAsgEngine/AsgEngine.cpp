#include <boost/python/module.hpp>
#include <boost/python/def.hpp>
#include <boost/python.hpp>
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <iostream>
#include <algorithm>
#include "AsgEngine.h"
#include "Dendrogram.hh"
#include "RegexExtractorLCSS.hh"

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

AsgEngine::AsgEngine(dict properties, bool debug_flag) :
  m_properties(properties), m_debug(debug_flag)
{
  m_max_depth = extract<int>(properties["max_depth"]);
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
          makeTries();
    }
}

void
AsgEngine::unsupervisedClustering()
{
  std::vector<std::string> pkt_content_list;
  BOOST_LOG_TRIVIAL(debug) << "Entering unsupervisedClustering" << std::endl;
  std::cout << "In makeTries" << std::endl;
  std::vector<std::vector<boost::shared_ptr<Packet> > >::const_iterator cit =
    m_detector_report.getAttackStartIterator();
  int cnt = 0;
  // We expect only one group of packets containing multiple attacks
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
          pkt_content_list.push_back(pkt_payload);
          pit++;
          pkt_cnt++;
        }
      cnt++;
      cit++;
    }
  Dendrogram dg(m_properties,pkt_content_list);
  dg.makeDistMtrx();
  boost::shared_ptr<tree<TreeNode> > dgram = dg.makeDendrogram();
  BOOST_LOG_TRIVIAL(debug)   << "After makeDendrogram" << std::endl;
  std::vector<std::set<std::string> > similar_string_sets =
    dg.findDisjointStringSets();
  BOOST_LOG_TRIVIAL(debug)   << "Number of similar string sets " <<
    similar_string_sets.size() << std::endl;

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


      string_set_count++;
    }

}
