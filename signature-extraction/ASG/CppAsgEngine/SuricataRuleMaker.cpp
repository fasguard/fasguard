#include <sstream>
#include "SuricataRuleMaker.hpp"

unsigned int SuricataRuleMaker::sid_cnt =
  SuricataRuleMaker::SnortCustomRuleOffset;

SuricataRuleMaker::SuricataRuleMaker(std::string protocol, std::string ip1,
                                     std::string port1,std::string ip2,
                                     std::string port2) : m_protocol(protocol),
                                                          m_ip1(ip1),
                                                          m_port1(port1),
                                                          m_ip2(ip2),
                                                          m_port2(port2)
{
}

SuricataRuleMaker::~SuricataRuleMaker()
{}

std::string
SuricataRuleMaker::makeContentRule(std::string &signature,
                                   unsigned int sid,
                                   unsigned int rev)
{
  std::string content = "|"+signature+"|";
  std::string rule_header = "alert "+m_protocol+" "+m_ip1+" "+m_port1+" -> "+
    m_ip2+" "+m_port2+" ";
  std::ostringstream ost;
  ost << sid;
  std::string sid_str = ost.str();
  ost.str("");
  ost << rev;
  std::string rev_str = ost.str();
  std::string rule_body = "(msg:\"RePS generated rule\";  content:\""+
    content+"\"; sid:"+sid_str+"; rev:"+rev_str+"; )\n";
  sid_cnt++;
  return rule_header+rule_body;
}
