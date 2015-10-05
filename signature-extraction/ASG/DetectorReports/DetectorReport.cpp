#include <boost/python/module.hpp>
#include <boost/python/def.hpp>
#include <boost/python.hpp>
#include <iostream>
#include "DetectorReport.h"

using namespace boost::python;

BOOST_PYTHON_MODULE(detector_xmt_ext)
{

  class_<DetectorReport>("DetectorReport", init<>())
    .def("appendAttack", &DetectorReport::appendAttack)
    .def("appendPacket", &DetectorReport::appendPacket)
    ;
}

DetectorReport::DetectorReport()
{}

DetectorReport::~DetectorReport()
{}

void
DetectorReport::appendAttack()
{
  m_attacks.push_back(std::vector<boost::shared_ptr<Packet> >());
}

void
DetectorReport::appendPacket(double time, int protocol, int sport, int dport,
                    std::string payload, float prob_attack)
{
  std::cout << "TIME: " << time << std::endl;
  m_attacks.back().push_back(boost::shared_ptr<Packet>(new
                                                       Packet(time,
                                                              protocol,
                                                              sport,dport,
                                                              payload,
                                                              prob_attack)));
}
