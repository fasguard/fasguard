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
#include <boost/math/distributions/normal.hpp>
#include <boost/math/distributions/poisson.hpp>

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

    The number of peers is considered anomalous under a specific
    probability distribution when the survival function evaluates to a
    value lower that this. This value must be between 0.0 and 1.0,
    though only values close to 0.0 are useful. The closer to 0.0 it
    is, the fewer detections there will be.
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
    if (generation < mCurrentGeneration)
    {
        LOG(LOG_ERR,
            "Regressed from generation %" PRI_GENERATION_T " to %"
                PRI_GENERATION_T ". This should not have happened.",
            mCurrentGeneration,
            generation);
        return;
    }
    else if (generation > mCurrentGeneration)
    {
        LOG(LOG_DEBUG,
            "done with generation %" PRI_GENERATION_T
                ", starting generation %" PRI_GENERATION_T,
            mCurrentGeneration,
            generation);
        mCurrentGeneration = generation;

        cleanup();
    }

    // Extract the IP addresses.
    IPAddress srcAddress;
    IPAddress dstAddress;
    if (!IPAddress::parse_packet(
        srcAddress, dstAddress,
        pcap_header->caplen - layer2_hlen, packet + layer2_hlen))
    {
        return;
    }

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
    struct timeval result;
    result.tv_sec = (time_t)(x.tv_sec * y);

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

    // Scan mLastSeen in ascending generation order, removing data for
    // older generations.
    for (auto it = mLastSeen.get<0>().begin();
        it != mLastSeen.get<0>().end() &&
            it->first < mCurrentGeneration - MAX_EMPTY_GENERATIONS;
        it = mLastSeen.get<0>().erase(it))
    {
        LOG(LOG_DEBUG,
            "Removing histogram for %s "
            "from generation %" PRI_GENERATION_T " "
            "(%" PRI_GENERATION_T " generations ago)",
            it->second.toString().c_str(),
            it->first,
            mCurrentGeneration - it->first);
        mPeers.erase(it->second);
        mHistograms.erase(it->second);
    }
}

void AnomalyDetector::process_host(
    IPAddress const & host)
{
    auto peers_it = mPeers.find(host);
    auto histogram_it = mHistograms.find(host);

    if (peers_it == mPeers.end() && histogram_it == mHistograms.end())
    {
        // Nothing to process yet.
        return;
    }

    Histogram * histogram;
    if (histogram_it == mHistograms.end())
    {
        // Make a new histogram.
        histogram = &mHistograms[host];

        // Set the histogram's generation to one before when the host
        // was last (and first) seen. It will be incremented to the
        // correct value below. NOTE: until it's incremented, the
        // below code must correctly handle integer wrap-around.
        histogram->generation =
            mLastSeen.get<1>().find(host)->first - 1;
    }
    else
    {
        histogram = &histogram_it->second;
    }

    if (histogram->generation + 1 >= mCurrentGeneration)
    {
        // The histogram is already up to date.
        return;
    }

    // Get the number of peers for the generation after the histogram was last
    // updated.
    size_t num_peers;
    if (peers_it == mPeers.end())
    {
        num_peers = 0;
    }
    else
    {
        num_peers = peers_it->second.size();
        mPeers.erase(peers_it);
    }

    // Update the histogram for the generation after the histogram was last
    // updated.
    histogram->next_value(num_peers);
    ++histogram->generation;

    // Update the histogram for any generations where the host was not seen.
    while (histogram->generation + 1 < mCurrentGeneration)
    {
        num_peers = 0;
        histogram->next_value(num_peers);
        ++histogram->generation;
    }

    if (check_for_anomalies(host, *histogram, num_peers))
    {
        if (!is_anomalous(host))
        {
            LOG(LOG_DEBUG, "Host became anomalous: %s",
                host.toString().c_str());
        }

        mAnomalous.insert(host);
    }
    else
    {
        if (is_anomalous(host))
        {
            LOG(LOG_DEBUG, "Host is no longer anomalous: %s",
                host.toString().c_str());
        }

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
    @brief Determine if @p datum is anomalous under the normal
           distribution, given @p mean and @p stddev.
*/
static bool datum_is_anomalous_normal(
    double mean,
    double stddev,
    size_t datum)
{
    if (stddev <= 0.0)
    {
        // Anything other than the mean is anomalous. Use double
        // comparison instead of integer comparison in case of large
        // values.
        return round(mean) != (double)datum;
    }

    boost::math::normal normal(mean, stddev);

    return
        boost::math::cdf(boost::math::complement(normal, datum)) <
            ANOMALOUS_THRESHOLD;
}

/**
    @brief Determine if @p datum is anomalous under the poisson
           distribution, given @p mean.
*/
static bool datum_is_anomalous_poisson(
    double mean,
    size_t datum)
{
    boost::math::poisson poisson(mean);

    return
        boost::math::cdf(boost::math::complement(poisson, datum)) <
            ANOMALOUS_THRESHOLD;
}

/**
    @brief Determine if @p datum is anomalous, given @p mean and @p stddev.
*/
static bool datum_is_anomalous(
    double mean,
    double stddev,
    size_t datum)
{
    if (mean <= 0.0)
    {
        // Datum should have already been integrated into mean so this
        // situation should not be possible.
        LOG(LOG_ERR,
            "Invalid distribution "
            "[mean = %g, stddev = %g, datum = %zu].",
            mean, stddev, datum);
        return true;
    }

    return datum_is_anomalous_normal(mean, stddev, datum) &&
        datum_is_anomalous_poisson(mean, datum);
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

    auto it = mLastSeen.get<1>().find(a);
    if (it == mLastSeen.get<1>().end())
    {
        mLastSeen.get<1>().insert(
            std::pair<generation_t, IPAddress>(mCurrentGeneration, a));
    }
    else if (it->first != mCurrentGeneration)
    {
        mLastSeen.get<1>().replace(
            it,
            std::pair<generation_t, IPAddress>(mCurrentGeneration, a));
    }
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
