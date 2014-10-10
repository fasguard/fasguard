/**
    @file

    This implements a simple version of the Host Peering anomaly detector from
    the original SMITE project. Host Peering tracks the number of "peers" each
    host has over time. For example, Host Peering can detect an anomaly when a
    computer that usually only interacts with less than five other computers
    per minute is becomes part of a botnet and starts interacting with dozens or
    more computers per minute.

    First, data is collected by tracking who talks to whom within a generation
    (#GENERATION_INTERVAL). At the end of each generation, all the data about
    who talks to whom is condensed into a per-host count of peer hosts. The
    per-host count is then added to a per-host histogram and compared against
    that histogram for anomalies.

    @todo Provide a brief description of SMITE?

    @todo Implement the CDF/SF detections.
*/

#include <sys/time.h>

#include "anomaly.hpp"
#include "logging.hpp"


/**
    @brief The length of a single generation.
*/
static struct timeval const GENERATION_INTERVAL = {
    .tv_sec = 60,
    .tv_usec = 0,
};

/**
    @brief Alpha value for the fast EMA.

    Host Peering uses <a
    href="http://en.wikipedia.org/wiki/Moving_average#Exponential_moving_average">exponential
    moving averages</a> (EMAs) of the number of peers each host has per
    generation. There are two EMAs used, one that decays quickly (#ALPHA_FAST)
    and one that decays slowly (#ALPHA_SLOW). For either, alpha must be less
    than one and a higher alpha discounts past observations more quickly.
    #ALPHA_FAST should be greater than #ALPHA_SLOW.

    @note (2-alpha)/(2.8854*alpha) gives the number of generations in which the
          weights diminish by a factor of two (i.e., gives the half-life).

    @sa ALPHA_SLOW
*/
#define ALPHA_FAST 0.3

/**
    @brief Alpha value for the slow EMA.

    @sa ALPHA_FAST
*/
#define ALPHA_SLOW 0.05

/**
    @brief Threshold for a single generation to be considered anomalous.

    If any host has more than this many peers in a single generation, it is
    considered anomalous.
*/
#define INSTANTANEOUS_THRESHOLD 20

/**
    @brief Threshold for the EMA fasguard to be considered anomalous.

    If the EMA fasguard for any host exceeds this value, it is considered anomalous.

    @sa ALPHA_FAST
*/
#define EMA_FASGUARD_THRESHOLD 15.0

/**
    @brief Threshold for the EMA slow to be considered anomalous.

    If the EMA slow for any host exceeds this value, it is considered anomalous.

    @sa ALPHA_SLOW
*/
#define EMA_SLOW_THRESHOLD 10.0


AnomalyData::AnomalyData()
{
}

AnomalyData::~AnomalyData()
{
}

void AnomalyData::process_packet(
    struct pcap_pkthdr const * pcap_header,
    uint8_t const * packet)
{
    (void)pcap_header;
    (void)packet;
}

AnomalyData::Histogram::Histogram() :
    average(0.0),
    mean_of_squares(0.0),
    ema_fast(-1.0),
    ema_slow(-1.0),
    ema_fast_squared(0.0),
    ema_slow_squared(0.0),
    count(0)
{
}
