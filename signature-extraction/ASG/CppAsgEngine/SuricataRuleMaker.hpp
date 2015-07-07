#ifndef SURICATA_RULE_MAKER_HPP
#define SURICATA_RULE_MAKER_HPP
#include <string>
#include <vector>
#include <set>
#include <string>
#include <map>
#include <memory>

/**
 * This class takes a signature string and turns it into a Suricata rule.
 *
 * As input, we take the signature string, an SID and a REV number, as well as
 * five tuple information. A rule is generated and returned.
 */
class SuricataRuleMaker
{
public:
  static const int SnortCustomRuleOffset = 10000;
  /**
   * Constructor. Fields common to all rules to be generated are intialized
   * here.
   * @param protocol This is tcp, udp or any.
   * @param ip1 One of the IP addresses.
   * @param port1 The port number associated with IP1. Can be any.
   * @param ip2 The other IP address.
   * @param port2 Port associated with ip2.
   */
  SuricataRuleMaker(std::string protocol, std::string ip1, std::string port1,
                    std::string ip2,std::string port2);
  ~SuricataRuleMaker();
  /**
   * Given a signature string in blank-separated hex, a Snort rule is returned.
   *
   * @param sig_vec Signatures as blank-separated hex with each being a
   *    maximum of 255 bytes.
   * @param sid The signature id number.
   * @param rev The sid version number.
   * @return Snort rule.
   */
  std::string
  makeContentRule(std::vector<std::string> &sig_vec,
                  unsigned int sid = sid_cnt,
                  unsigned int rev = 0);
  /**
   * Given a vector of ngram fragments, a Snort rule consisting of a pcre
   * containing an alternation of the various fragments is returned.
   *
   * @param ngram_frag_list A vector of ngram fragments to use in the signature.
   * @param sid The signature id number.
   * @param rev The sid version number.
   * @return Snort Rule.
   */
  std::string
  makePcreRule(std::vector<std::string> &ngram_frags,
               unsigned int sid = sid_cnt,
               unsigned int rev = 0);

protected:
  static unsigned int sid_cnt;
  std::string m_protocol;
  std::string m_ip1;
  std::string m_port1;
  std::string m_ip2;
  std::string m_port2;
  int m_rev;
};

#endif
