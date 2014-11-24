#include <boost/python/module.hpp>
#include <boost/python/def.hpp>
#include <boost/shared_ptr.hpp>
#include <string>
#include <vector>

/**
 * This class is the C++ representation of the data from a packet and its
 * corresponding metadata.
 */
class Packet
{
 public:
  /**
   * Constructor for an object that contains a packet with all its data and
   * metadata to the current attack.
   * @param time Time from epoch including fraction of seconds.
   * @param service IP code for service.
   * @param sport Source port for TCP or UDP.
   * @param dport Destination port for TCP or UDP.
   * @param payload Binary string containing packet payload.
   * @param prob_attack Detectors estimate of the probability that this packet
   *            is part of the attack.
   */
  Packet(double time, int service, int sport, int dport, std::string payload,
         float prob_attack) : time_(time),service_(service),sport_(sport),
    dport_(dport),m_payload(payload),prob_attack_(prob_attack)
  {}
  /**
   * Destructor.
   */
  ~Packet()
    {}
  /**
   * Accessor for packet payload.
   * @return Payload as string.
   */
  const std::string &
    getPayload() const
  {
    return m_payload;
  }
 private:
  double time_;
  int service_;
  int sport_;
  int dport_;
  std::string m_payload;
  float prob_attack_;
};

/**
 * This class is the C++ representation of a detector report. It is populated
 * from Python from the DetectorEvent class. At some point, this will be updated
 * so that multiple DetectorEvents will be aggregated in a DetectorReport.
 * Currently, this is set up so that one DetectorEven becomes one
 * DetectorReport.
 */
class DetectorReport
{
 public:
  /**
   * Constructor.
   */
  DetectorReport();
  /**
   * Destructor.
   */
  ~DetectorReport();
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
   * Accessor for start iterator for vector that contains Packets for a single
   * attack.
   * @return Start iterator for list of vectors where each vector contsins
   *    packets for a single attack.
   */
  std::vector<std::vector<boost::shared_ptr<Packet> > >::const_iterator
    getAttackStartIterator()
    {
      return m_attacks.begin();
    }
  /**
   * Accessor for end iterator for vector that contains Packets for a single
   * attack.
   * @return End iterator for list of vectors where each vector contsins
   *    packets for a single attack.
   */
  std::vector<std::vector<boost::shared_ptr<Packet> > >::const_iterator
    getAttackEndIterator()
    {
      return m_attacks.end();
    }
 private:
  std::vector<std::vector<boost::shared_ptr<Packet> > > m_attacks;
};
