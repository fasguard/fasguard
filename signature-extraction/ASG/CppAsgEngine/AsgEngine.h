#ifndef ASGENGINE_H
#define ASGENGINE_H
#include <boost/python/module.hpp>
#include <boost/python/def.hpp>
#include <string>
#include <vector>
#include "../DetectorReports/DetectorReport.h"
#include "Trie.h"
#include "AbstractTrieNodeFactory.h"
#include "MemoryTrieNodeFactory.h"
#include "bloomfilter.hpp"

/**
 * This class performs the actual work in extracting signatures from a detector
 * report. Each step is invoked from the corresponding Python AsgEngine class.
 */
class AsgEngine
{
 public:
  /**
   * Constructor.
   * @param properties Properties dictionary passed down by Python code.
   * @param debug_flag If true, various debug information is printed out.
   */
  AsgEngine(boost::python::dict properties, bool debug_flag);
  /**
   * Destructor.
   */
  ~AsgEngine();
  /**
   * Set flags for entire detector event report.
   * @param multiple_attack_flag True if the detector event contains multiple
   *    instances of the same attack. If false, all the data corresponds to
   *    a single attack.
   * @param attack_boundaries_flag True if the multiple_attack_flag is true and
   *    the detector has separated the given instances of the attack. If the
   *    multiple_attack_flag is true and the attack_boundaries_flag is false,
   *    packets for multiple attacks are sent together and must be separated by
   *    clustering. If the multiple_attack_flag is false, the value of the
   *    attack_boundaries_flag is not meaningful.
   */
  void setDetectorEventFlags(bool multiple_attack_flag,
                             bool attack_boundaries_flag);
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
  /**
   *  Method to create a set of candidate signature strings which are then
   *    filtered using benign traffic. The method used for creating the
   *    candidate signatures depends on multi-attack metadata. The three
   *    possible methods are:
   *    1) If the multiAttackFlag is false, we produce tries that store all
   *       n-grams within the range of lengths and all are signature candidates.
   *    2) If the multiAttackFlag is true but the attackBoundaryFlag is false,
   *       we use a general local-alignment based clustering to find similar
   *       large strings within clustered packets assumed to be corresponding
   *       packets across attacks.
   *    3) If the multiAttackFlag is true and the attackBoundaryFlag is true,
   *       we create clusters such that each cluster is constrained to contain
   *       at most one packet from each attack instance.
   */
  void makeCandidateSignatureStringSet();

 protected:
  /**
   * Where we are told that there are multiple attacks but we are not given
   * information about attack boundaries, we perform unsupervised clustering.
   */
  void unsupervisedClustering();
  /**
   * Filter list of signature fragments. Each fragment must have at least
   * one that is not in the Bloom filter.
   * @param bf Bloom filter.
   * @param sig_frags vector of strings that will be part of the signature.
   * @return Vector of strings that survive filtering.
   */
  std::vector<std::string>
    filtSigFrags(fasguard::bloom_filter &bf, std::vector<std::string> &frag_pieces);
 private:
  DetectorReport m_detector_report;
  std::vector<std::vector<boost::shared_ptr<Trie> > > m_trie_attack_list;
  int m_max_depth;
  int m_min_depth;
  std::string m_bloom_filter_dir;
  boost::python::dict m_properties;
  bool m_debug;
  bool m_multiple_attack_flag;
  bool m_attack_boundaries_flag;
};
#endif
