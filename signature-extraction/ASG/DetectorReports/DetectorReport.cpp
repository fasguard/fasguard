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
  attacks_.push_back(std::vector<Packet *>());
}

void
DetectorReport::appendPacket(double time, int service, int sport, int dport,
                    std::string payload, float prob_attack)
{
  std::cout << "TIME: " << time << std::endl;
  attacks_.back().push_back(new Packet(time,service,sport,dport,payload,
                                       prob_attack));
}
