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
    @brief Create and initialize the data needed by #anomaly_packet_callback().

    @return A pointer to opaque data. If NULL is returned, there was an error
            and the error was #LOG()ed appropriately.

    @sa free_anomaly_data
*/
void * new_anomaly_data();

/**
    @brief Free the data returned by #new_anomaly_data().
*/
void free_anomaly_data(void * data);

/**
    @brief Process a single packet in the anomaly detector.

    This function is suitable for passing as the callback to pcap_loop.
*/
void anomaly_packet_callback(
    uint8_t * user,
    struct pcap_pkthdr const * h,
    uint8_t const * bytes);

#endif
