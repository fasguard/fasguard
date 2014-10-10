/**
    @file
    @brief Anomaly detection code.
*/

#ifndef _HOST_PEERING_ANOMALY_H
#define _HOST_PEERING_ANOMALY_H

#include <inttypes.h>
#include <unordered_map>
#include <pcap/pcap.h>
#include <unordered_set>

#include "network.hpp"

/**
    @brief Number of bytes needed from the beginning of each packet.

    @todo Pick a more appropriate value for this.
*/
#define ANOMALY_SNAPLEN 128

/**
    @brief This contains all the state for the anomaly detector.
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
    /**
        @brief Data about the history of the number of peers for a single IP.
    */
    struct Histogram
    {
        Histogram();

        /**
            @brief Cumulative mean of the number of peers we've had per
                   generation.

            This is what you usually think of as a mean
            (sum-of-values/number-of-items), but is calculated in a way that
            doesn't require keeping track of all the items.
        */
        double average;

        /**
            @brief Mean of the square of each number of peers.

            One way of calculating the variance is the useful identity that the
            variance is the mean of the squares minus the square of the mean
            (http://en.wikipedia.org/wiki/Computational_formulas_for_the_variance).
            Just as we keep track of the mean, we keep track of the mean of the
            squares.

            @note There are two values typically referred to as "variance".
                  What we're calculating is the absolute variance; when one is
                  taking a statistical sample, one calculates the sample
                  variance (which is what R's var() function returns), which
                  differs.
        */
        double mean_of_squares;

        /**
            @brief Fast exponential moving average.

            @sa ALPHA_FAST
        */
        double ema_fast;

        /**
            @brief Slow exponential moving average.

            @sa ALPHA_SLOW
        */
        double ema_slow;

        /**
            @brief Fast exponential moving average of the squares.

            This is used for calculating exponential moving variance.

            @sa ALPHA_FAST
        */
        double ema_fast_squared;

        /**
            @brief Slow exponential moving average of the squares.

            This is used for calculating exponential moving variance.

            @sa ALPHA_SLOW
        */
        double ema_slow_squared;

        /**
            @brief Number of data points used to build this histogram.
        */
        uint64_t count;
    };

    /**
        @brief Map from IP address to set of peer IP addresses.

        This is cleared at the end of each generation.
    */
    std::unordered_map<IPAddress, std::unordered_set<IPAddress>> mPeers;

    /**
        @brief Map from IP address to histogram for that IP.
    */
    std::unordered_map<IPAddress, Histogram> mHistograms;
};

#endif
