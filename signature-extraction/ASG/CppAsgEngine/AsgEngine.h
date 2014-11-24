#include <boost/python/module.hpp>
#include <boost/python/def.hpp>
#include <string>
#include <vector>
#include "../DetectorReports/DetectorReport.h"
#include "Trie.h"
#include "AbstractTrieNodeFactory.h"
#include "MemoryTrieNodeFactory.h"

/**
 * This class performs the actual work in extracting signatures from a detector
 * report. Each step is invoked from the corresponding Python AsgEngine class.
 */
class AsgEngine
{
 public:
  /**
   * Constructor.
   * @param max_depth Max depth of trie - longest allowed string.  Negative
   *    number means unlimited depth.
   */
  AsgEngine(boost::python::dict properties, bool debug_flag);
  /**
   * Destructor.
   */
  ~AsgEngine();
  /**
   * Inovoked to indicate a new instance of an attack. All subsequently
   * appended packets will be added to this new attack.
   */
  void appendAttack();
  /**
   * Appends a packet with all its data and metadata to the current attack.
   * @param time Time from epoch including fraction of seconds.
   * @param service IP code for service.
   * @param sport Source port for TCP or UDP.
   * @param dport Destination port for TCP or UDP.
   * @param payload Binary string containing packet payload.
   * @param prob_attack Detectors estimate of the probability that this packet
   *            is part of the attack.
   */
  void appendPacket(double time, int service, int sport, int dport,
                    std::string payload, float prob_attack);
  /**
   * For each packet in each attack, produce a trie.
   */
  void makeTries();
 private:
  DetectorReport m_detector_report;
  std::vector<std::vector<boost::shared_ptr<Trie> > > m_trie_attack_list;
  int m_max_depth;
  boost::python::dict m_properties;
  bool m_debug;
};
