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
    @brief Maximum number of generations to store data for a host without seeing
           traffic to/from that host.

    @sa GENERATION_INTERVAL, AnomalyData::cleanup()
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
:
    mFirstPacket(NULL),
    mCurrentGeneration(0),
    mPeers(),
    mHistograms(),
    mLastSeen()
{
}

AnomalyData::~AnomalyData()
{
    delete mFirstPacket;
    mFirstPacket = NULL;
}

void AnomalyData::process_packet(
    struct pcap_pkthdr const * pcap_header,
    uint8_t const * packet)
{
    (void)packet;

    if (mFirstPacket == NULL)
    {
        mFirstPacket = new struct timeval(pcap_header->ts);
    }

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

    //IPAddress srcAddress; // TODO: from packet
    //IPAddress dstAddress; // TODO: from packet

    if (mCurrentGeneration > 0)
    {
        // Process both hosts' data from previous generations.
        //process_host(srcAddress);
        //process_host(dstAddress);
    }

    //add_peers_one_direction(srcAddress, dstAddress);
    //add_peers_one_direction(dstAddress, srcAddress);
}

/** In-place subtract a timeval from another timeval. */
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

/** Multiply a timeval by an integer-like type. */
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

/** Determine if a timeval is greater than or equal to another timeval. */
static bool operator>=(
    struct timeval const & x,
    struct timeval const & y)
{
    return x.tv_sec > y.tv_sec ||
        (x.tv_sec == y.tv_sec && x.tv_usec >= y.tv_usec);
}

AnomalyData::generation_t AnomalyData::getGeneration(
    struct timeval const & when)
    const
{
    // Compute the difference between mFirstPacket and when.
    struct timeval remainder(when);
    remainder -= *mFirstPacket;

    // Compute a lower bound on the current generation, and decrement remainder
    // appropriately.
    AnomalyData::generation_t generation =
        remainder.tv_sec / (GENERATION_INTERVAL.tv_sec + 1);
    remainder -= GENERATION_INTERVAL * generation;

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

void AnomalyData::cleanup()
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

void AnomalyData::process_host(
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
    check_for_anomalies(host, histogram);

    // Update the histogram for any generations where the host was not seen.
    while (histogram.generation < mCurrentGeneration - 1)
    {
        histogram.next_value(0);
        ++histogram.generation;
        check_for_anomalies(host, histogram);
    }
}

void AnomalyData::check_for_anomalies(
    IPAddress const & host,
    AnomalyData::Histogram const & histogram)
{
    (void)host;
    (void)histogram;

    // TODO
}

void AnomalyData::add_peers_one_direction(
    IPAddress const & a,
    IPAddress const & b)
{
    mPeers[a].insert(b);
}

AnomalyData::Histogram::Histogram()
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

void AnomalyData::Histogram::next_value(
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
