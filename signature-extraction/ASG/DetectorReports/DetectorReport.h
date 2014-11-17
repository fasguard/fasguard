#include <boost/python/module.hpp>
#include <boost/python/def.hpp>
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
    dport_(dport),payload_(payload),prob_attack_(prob_attack)
  {}
  /**
   * Destructor.
   */
  ~Packet()
    {}
 private:
  double time_;
  int service_;
  int sport_;
  int dport_;
  std::string payload_;
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
   * Destructor/
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
 private:
  std::vector<std::vector<Packet *> > attacks_;
};
