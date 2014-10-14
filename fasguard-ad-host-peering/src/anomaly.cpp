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
*/

#include <cmath>
//#include <boost/math/distributions/normal.hpp> // TODO: uncomment
//#include <boost/math/distributions/poisson.hpp> // TODO: uncomment

#include "anomaly.hpp"
#include "logging.hpp"


/**
    @brief The length of a single generation.

    Setting this to too small of a value may adversely affect performance, see
    the implementation of #AnomalyDetector::getGeneration. Additionally, any
    per-generation processing would have to be performed more frequently.
*/
static struct timeval const GENERATION_INTERVAL = {
    .tv_sec = 60,
    .tv_usec = 0,
};

/**
    @brief Maximum number of generations to store data for a host without seeing
           traffic to/from that host.

    @sa GENERATION_INTERVAL, AnomalyDetector::cleanup()
*/
#define MAX_EMPTY_GENERATIONS (24 * 60)

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
    @brief Probability threshold under which a number is considered anomolous.

    The number of peers is considered anomalous under a specific probability
    distribution when the cumulative distribution function or survival function
    evaluates to a value lower that this. This value must be between 0.0 and
    1.0, though only values close to 0.0 are useful. The closer to 0.0 it is,
    the fewer detections there will be.
*/
#define ANOMALOUS_THRESHOLD 4e-9


AnomalyDetector::AnomalyDetector()
:
    mFirstPacket(NULL),
    mCurrentGeneration(0),
    mPeers(),
    mHistograms(),
    mLastSeen(),
    mAnomalous()
{
}

AnomalyDetector::~AnomalyDetector()
{
    delete mFirstPacket;
    mFirstPacket = NULL;
}

void AnomalyDetector::process_packet(
    struct pcap_pkthdr const * pcap_header,
    size_t layer2_hlen,
    uint8_t const * packet)
{
    // Initialize mFirstPacket if needed.
    if (mFirstPacket == NULL)
    {
        mFirstPacket = new struct timeval(pcap_header->ts);
    }

    // Get the current generation and do inter-generation processing if needed.
    generation_t generation = getGeneration(pcap_header->ts);
    if (generation != mCurrentGeneration)
    {
        LOG(LOG_DEBUG,
            "done with generation %" PRI_GENERATION_T
                ", starting generation %" PRI_GENERATION_T,
            mCurrentGeneration,
            generation);
        mCurrentGeneration = generation;

        cleanup();
    }

    // Determine the IP version and address field offsets.
    IPAddress::Version ip_version;
    size_t src_address_offset;
    size_t dst_address_offset;
    if (pcap_header->caplen >= layer2_hlen + 20 &&
        IP_VERSION(packet + layer2_hlen) == 4)
    {
        ip_version = IPAddress::IPv4;
        src_address_offset = 12;
        dst_address_offset = 16;
    }
    else if (pcap_header->caplen >= layer2_hlen + 40 &&
        IP_VERSION(packet + layer2_hlen) == 6)
    {
        ip_version = IPAddress::IPv6;
        src_address_offset = 8;
        dst_address_offset = 24;
    }
    else
    {
        return;
    }

    // Extract the IP addresses.
    IPAddress srcAddress(ip_version, packet, layer2_hlen + src_address_offset);
    IPAddress dstAddress(ip_version, packet, layer2_hlen + dst_address_offset);

    if (mCurrentGeneration > 0)
    {
        // Process both hosts' data from previous generations.
        process_host(srcAddress);
        process_host(dstAddress);
    }

    // Mark who peered with whom.
    add_peers_one_direction(srcAddress, dstAddress);
    add_peers_one_direction(dstAddress, srcAddress);
}

bool AnomalyDetector::is_anomalous(
    IPAddress const & addr)
    const
{
    return (bool)mAnomalous.count(addr);
}

/**
    @brief In-place subtract a timeval from another timeval.
*/
static struct timeval & operator-=(
    struct timeval & x,
    struct timeval const & y)
{
    x.tv_sec -= y.tv_sec;

    if (x.tv_usec >= y.tv_usec)
    {
        x.tv_usec -= y.tv_usec;
    }
    else
    {
        --x.tv_sec;
        x.tv_usec += 1000000 - y.tv_usec;
    }

    return x;
}

/**
    @brief Multiply a timeval by an integer-like type.
*/
template<typename Integer>
static struct timeval operator*(
    struct timeval const & x,
    Integer const & y)
{
    struct timeval result = {
        .tv_sec = (time_t)(x.tv_sec * y),
        .tv_usec = 0,
    };

    uintmax_t usec = (uintmax_t)x.tv_usec * y;
    result.tv_sec += usec / 1000000;
    result.tv_usec = usec % 1000000;

    return result;
}

/**
    @brief Determine if a timeval is greater than or equal to another timeval.
*/
static bool operator>=(
    struct timeval const & x,
    struct timeval const & y)
{
    return x.tv_sec > y.tv_sec ||
        (x.tv_sec == y.tv_sec && x.tv_usec >= y.tv_usec);
}

AnomalyDetector::generation_t AnomalyDetector::getGeneration(
    struct timeval const & when)
    const
{
    // Compute the difference between mFirstPacket and when.
    struct timeval remainder(when);
    remainder -= *mFirstPacket;

    generation_t generation = 0;

    // Iteratively compute potentially poor lower bounds on the current
    // generation, decrementing the remainder appropriately.
    generation_t generation_increment;
    do
    {
        generation_increment =
            remainder.tv_sec / (GENERATION_INTERVAL.tv_sec + 1);
        generation += generation_increment;
        remainder -= GENERATION_INTERVAL * generation_increment;
    } while (generation_increment > 0);

    // Use repeated subtraction (inefficient) to refine generation to the
    // correct value.
    while (remainder >= GENERATION_INTERVAL)
    {
        remainder -= GENERATION_INTERVAL;
        ++generation;
    }

    // At this point, generation is the current generation and remainder is the
    // amount of time from the beginning of the generation to when.

    return generation;
}

void AnomalyDetector::cleanup()
{
    if (mCurrentGeneration <= MAX_EMPTY_GENERATIONS)
    {
        LOG(LOG_DEBUG,
            "Software has not been running long enough to require cleanup.");
        return;
    }

    while (!mLastSeen.empty() &&
        mLastSeen.top().first < mCurrentGeneration - MAX_EMPTY_GENERATIONS)
    {
        LOG(LOG_DEBUG, "Removing histogram for %s",
            mLastSeen.top().second.toString().c_str());
        mPeers.erase(mLastSeen.top().second);
        mHistograms.erase(mLastSeen.top().second);
        mLastSeen.pop();
    }
}

void AnomalyDetector::process_host(
    IPAddress const & host)
{
    Histogram & histogram = mHistograms[host];
    if (histogram.generation >= mCurrentGeneration - 1)
    {
        // The histogram is already up to date.
        return;
    }

    // Get the number of peers for the generation after the histogram was last
    // updated.
    size_t num_peers;
    std::unordered_map<IPAddress, std::unordered_set<IPAddress>>::const_iterator
        peers_iterator = mPeers.find(host);
    if (peers_iterator == mPeers.cend())
    {
        num_peers = 0;
    }
    else
    {
        num_peers = peers_iterator->second.size();
        mPeers.erase(peers_iterator);
    }

    // Update the histogram for the generation after the histogram was last
    // updated.
    histogram.next_value(num_peers);
    ++histogram.generation;

    // Update the histogram for any generations where the host was not seen.
    while (histogram.generation < mCurrentGeneration - 1)
    {
        num_peers = 0;
        histogram.next_value(num_peers);
        ++histogram.generation;
    }

    if (check_for_anomalies(host, histogram, num_peers))
    {
        mAnomalous.insert(host);
    }
    else
    {
        mAnomalous.erase(host);
    }
}

/**
   @brief Calculate the standard deviation.
*/
static double stddev_calc(
    double mean_of_squares,
    double mean)
{
    double const variance = mean_of_squares - mean * mean;

    // Handle rounding issues.
    if (variance > -1e-9 && variance <= 0.0)
    {
        return 0.0;
    }

    return sqrt(variance);
}

/**
    @brief Determine if @p datum is anomalous, given @p mean and @p stddev.
*/
static bool datum_is_anomalous(
    double mean,
    double stddev,
    size_t datum)
{
    #if 0 // TODO
    boost::math::normal_distribution normal(mean, stddev);
    boost::math::poisson_distribution poisson(mean);

    return boost::math::cdf(normal, datum) < ANOMALOUS_THRESHOLD ||
        boost::math::cdf(boost::math::complement(normal, datum)) <
            ANOMALOUS_THRESHOLD ||
        boost::math::cdf(poisson, datum) < ANOMALOUS_THRESHOLD ||
        boost::math::cdf(boost::math::complement(normal, datum)) <
            ANOMALOUS_THRESHOLD;
    #else
    (void)mean;
    (void)stddev;
    (void)datum;
    return false;
    #endif
}

bool AnomalyDetector::check_for_anomalies(
    IPAddress const & host,
    AnomalyDetector::Histogram const & histogram,
    size_t num_peers)
{
    (void)host; // This could be used for LOGging in the future.

    if (datum_is_anomalous(
        histogram.average,
        stddev_calc(histogram.mean_of_squares, histogram.average),
        num_peers))
    {
        return true;
    }

    if (datum_is_anomalous(
        histogram.ema_fast,
        stddev_calc(histogram.ema_fast_squared, histogram.ema_fast),
        num_peers))
    {
        return true;
    }

    if (datum_is_anomalous(
        histogram.ema_slow,
        stddev_calc(histogram.ema_slow_squared, histogram.ema_slow),
        num_peers))
    {
        return true;
    }

    return false;
}

void AnomalyDetector::add_peers_one_direction(
    IPAddress const & a,
    IPAddress const & b)
{
    mPeers[a].insert(b);
}

AnomalyDetector::Histogram::Histogram()
:
    average(0.0),
    mean_of_squares(0.0),
    ema_fast(-1.0),
    ema_slow(-1.0),
    ema_fast_squared(0.0),
    ema_slow_squared(0.0),
    generation(0),
    count(0)
{
}

/**
    @brief Calculate a new average.

    @param[in] previous_average The average when the previous value was added.
    @param[in] new_value The value to add.
    @param[in] new_count The total number of values, including @p new_value.
*/
static double new_average_calc(
    double previous_average,
    double new_value,
    size_t new_count)
{
    return (new_value + (new_count - 1) * previous_average) / new_count;
}

/**
    @brief Calculate a new exponential moving average.

    @param[in] previous_ema The EMA when the previous value was added.
    @param[in] new_value The value to add.
    @param[in] alpha Alpha value. See #ALPHA_FAST for a description.
*/
static double new_ema_calc(
    double previous_ema,
    double new_value,
    double alpha)
{
    return (alpha * new_value) + ((1.0 - alpha) * previous_ema);
}

void AnomalyDetector::Histogram::next_value(
    size_t value)
{
    double const value_squared = (double)value * (double)value;

    ++count;

    // Incorporate value into the normal averages.
    average = new_average_calc(average, value, count);
    mean_of_squares = new_average_calc(mean_of_squares, value_squared, count);

    if (count == 1)
    {
        // Initialize the EMAs with value.
        ema_fast = value;
        ema_slow = value;
        ema_fast_squared = value_squared;
        ema_slow_squared = value_squared;
    }
    else
    {
        // Incorporate value into the EMAs.
        ema_fast = new_ema_calc(ema_fast, value, ALPHA_FAST);
        ema_slow = new_ema_calc(ema_slow, value, ALPHA_SLOW);
        ema_fast_squared = new_ema_calc(
            ema_fast_squared, value_squared, ALPHA_FAST);
        ema_slow_squared = new_ema_calc(
            ema_slow_squared, value_squared, ALPHA_SLOW);
    }
}
