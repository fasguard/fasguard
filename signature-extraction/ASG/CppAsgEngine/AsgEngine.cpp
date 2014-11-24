#include <boost/python/module.hpp>
#include <boost/python/def.hpp>
#include <boost/python.hpp>
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <iostream>
#include <algorithm>
#include "AsgEngine.h"

using namespace boost::python;

BOOST_PYTHON_MODULE(asg_engine_ext)
{

  class_<AsgEngine>("AsgEngine", init<dict,bool>())
    .def("appendAttack", &AsgEngine::appendAttack)
    .def("appendPacket", &AsgEngine::appendPacket)
    .def("makeTries",&AsgEngine::makeTries)
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
