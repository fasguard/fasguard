/**
    @file
    @brief Anomaly detection code.
*/

#ifndef _HOST_PEERING_ANOMALY_H
#define _HOST_PEERING_ANOMALY_H

#include <inttypes.h>
#include <pcap/pcap.h>

/**
    @brief Number of bytes needed from the beginning of each packet.

    @todo Pick a more appropriate value for this.
*/
#define ANOMALY_SNAPLEN 128

/**
    @brief This contains all the state for the anomaly detector.

    @todo Add a map from IP address to histogram
    @todo Add a map from IP address to set of peer IP addresses
*/
class AnomalyData
{
public:
    AnomalyData();

    ~AnomalyData();

    /**
        @brief Process a single packet in the anomaly detector.
    */
    void process_packet(
        struct pcap_pkthdr const * pcap_header,
        uint8_t const * packet);

protected:
    // TODO
};

#endif
