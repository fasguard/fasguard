#include <sstream>
#include <iomanip>
#include "SuricataRuleMaker.hpp"

unsigned int SuricataRuleMaker::sid_cnt =
  SuricataRuleMaker::SnortCustomRuleOffset;

SuricataRuleMaker::SuricataRuleMaker(std::string action, std::string protocol,
                                     std::string ip1, std::string port1,
                                     std::string ip2,
                                     std::string port2) : m_action(action),
                                                          m_protocol(protocol),
                                                          m_ip1(ip1),
                                                          m_port1(port1),
                                                          m_ip2(ip2),
                                                          m_port2(port2)
{
}

SuricataRuleMaker::~SuricataRuleMaker()
{}

std::string
SuricataRuleMaker::makeContentRule(std::vector<std::string> &sig_vec,
                                   unsigned int sid,
                                   unsigned int rev)
{
  std::vector<std::string> content_vec;

  std::vector<std::string>::iterator sit = sig_vec.begin();
  while(sit != sig_vec.end())
    {
      content_vec.push_back("|"+(*sit)+"|");
      sit++;
    }
  std::string rule_header = m_action +" "+m_protocol+" "+m_ip1+" "+m_port1+
    " -> "+ m_ip2+" "+m_port2+" ";
  std::ostringstream ost;
  ost << sid;
  std::string sid_str = ost.str();
  ost.str("");
  ost << rev;
  std::string rev_str = ost.str();
  std::string rule_body = "(msg:\"FASGuard generated rule, SID=  "+sid_str+
    "\";  ";
  std::vector<std::string>::iterator cit = content_vec.begin();
  while(cit != content_vec.end())
    {
      rule_body += "content:\""+
        *cit+"\"; ";
      cit++;
    }
  rule_body += "sid:"+sid_str+"; rev:"+rev_str+"; )\n";
  sid_cnt++;
  return rule_header+rule_body;
}

std::string
SuricataRuleMaker::makePcreRule(std::vector<std::string> &ngram_frags,
                                unsigned int sid, unsigned int rev)
{
  std::string rule_header = m_action+" "+m_protocol+" "+m_ip1+" "+m_port1+
    " -> "+
    m_ip2+" "+m_port2+" ";
  std::ostringstream ost;
  ost << sid;
  std::string sid_str = ost.str();
  ost.str("");
  ost << rev;
  std::string rev_str = ost.str();

  std::string pcre;
  std::stringstream ss;

  ss << "/(";

  for(std::vector<std::string>::iterator sit=ngram_frags.begin();
      sit != ngram_frags.end();
      sit++)
    {
      for(unsigned int i=0;i<(*sit).size();i++)
        {
          ss << std::hex << std::setw(2) <<
            std::setfill('0') << "\\x" <<(0xff & (unsigned int)((*sit)[i]));
        }
      ss << "|";
    }
  ss << ")/";
  pcre = ss.str();
  std::string rule_body = "(msg:\"RePS generated rule\";  pcre:\""+
    pcre+"\"; sid:"+sid_str+"; rev:"+rev_str+"; )\n";
  sid_cnt++;
  return rule_header+rule_body;
}
