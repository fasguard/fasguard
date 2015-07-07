/**
    @file
    @brief Anomaly detection code.
*/

#ifndef HOST_PEERING_ANOMALY_H
#define HOST_PEERING_ANOMALY_H

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <cinttypes>
#include <pcap/pcap.h>
#include <sys/time.h>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "network.hpp"

/**
    @brief Number of bytes needed from the beginning of each packet.
*/
#define ANOMALY_SNAPLEN 65535

/**
    @brief This contains all the state for the anomaly detector.
*/
class AnomalyDetector
{
public:
    AnomalyDetector();

    ~AnomalyDetector();

    /**
        @brief Process a single packet in the anomaly detector.
    */
    void process_packet(
        struct pcap_pkthdr const * pcap_header,
        size_t layer2_hlen,
        uint8_t const * packet);

    /**
        @brief Return whether the specified host is currently considered to be
               anomalous.
    */
    bool is_anomalous(
        IPAddress const & addr)
        const;

protected:
    /**
        @brief Type for a generation identifier.

        @sa PRI_GENERATION_T
    */
    typedef uint64_t generation_t;

    /**
        @brief Macro for using #AnomalyDetector::generation_t with printf.

        @sa AnomalyDetector::generation_t
    */
    #define PRI_GENERATION_T PRIu64

    /**
        @brief Data about the history of the number of peers for a single IP.
    */
    struct Histogram
    {
        Histogram();

        /**
            @brief Update the histogram with a new value.

            @note This does not update #generation.
        */
        void next_value(
            size_t value);

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
            @brief Generation of the latest data point in this histogram.
        */
        generation_t generation;

        /**
            @brief Number of data points used to build this histogram.
        */
        uint64_t count;
    };

    /**
        @brief Get the generation that corresponds to @p when.

        The generation counts from zero, so this function calculates
        <tt>(when - *#mFirstPacket) / #GENERATION_INTERVAL</tt>.
    */
    generation_t getGeneration(
        struct timeval const & when)
        const;

    /**
        @brief Remove old data.

        Remove any histograms that haven't been updated in
        #MAX_EMPTY_GENERATIONS generations.
    */
    void cleanup();

    /**
        @brief Update the histogram for a single host, and alert for any
               anomalies.
    */
    void process_host(
        IPAddress const & host);

    /**
        @brief Check a histogram for anomalies.

        @retval true There is an anomaly.
        @retval false There are no anomalies.
    */
    bool check_for_anomalies(
        IPAddress const & host,
        Histogram const & histogram,
        size_t num_peers);

    /**
        @brief Do the processing to note that @p b is a peer of @p a, but not
               vice versa.
    */
    void add_peers_one_direction(
        IPAddress const & a,
        IPAddress const & b);

    /**
        @brief When the first packet was seen.

        If this is NULL, then no packet has been seen yet.
    */
    struct timeval const * mFirstPacket;

    /**
        @brief The current generation.
    */
    generation_t mCurrentGeneration;

    /**
        @brief Map from IP address to set of peer IP addresses.

        This is cleared at the end of each generation.
    */
    std::unordered_map<IPAddress, std::unordered_set<IPAddress>> mPeers;

    /**
        @brief Map from IP address to histogram for that IP.
    */
    std::unordered_map<IPAddress, Histogram> mHistograms;

    /**
        @brief Store when each IPAddress was last seen.

        This is a container of std::pair<generation_t, IPAddress>,
        with an ordered non-unique index on the generation and a
        hashed unique index on the IPAddress. The first index enables
        finding IPAddresses that haven't been updated in a long time.
        The second index enables updating the generation for a
        specific IPAddress.
    */
    boost::multi_index::multi_index_container<
        std::pair<generation_t, IPAddress>,
        boost::multi_index::indexed_by<
            boost::multi_index::ordered_non_unique<
                boost::multi_index::member<
                    std::pair<generation_t, IPAddress>,
                    generation_t,
                    &std::pair<generation_t, IPAddress>::first
                    >
                >,
            boost::multi_index::hashed_unique<
                boost::multi_index::member<
                    std::pair<generation_t, IPAddress>,
                    IPAddress,
                    &std::pair<generation_t, IPAddress>::second
                    >
                >
            >
        >
        mLastSeen;

    /**
        @brief Set of IPAddresses that are currently considered anomalous.
    */
    std::unordered_set<IPAddress> mAnomalous;
};

#endif
