/**
    @file
    @brief Main code for the host-peering anomaly detector.
*/

#include <cstdlib>
#include <getopt.h>
#include <new>
#include <pcap/pcap.h>

#include "anomaly.hpp"
#include "logging.hpp"


/**
    @brief Read timeout (in milliseconds) for pcap_open_live.
*/
#define PCAP_READ_TIMEOUT 1000


/**
    @brief Print a help message.

    @todo Actually print a help message here.
*/
static void print_help()
{
}

/**
    @brief Handle a single packet.

    This function is suitable for passing as the callback to pcap_loop.
*/
static void packet_callback(
    uint8_t * user,
    struct pcap_pkthdr const * h,
    uint8_t const * bytes)
{
    AnomalyDetector * anomaly_detector = (AnomalyDetector *)user;
    anomaly_detector->process_packet(h, bytes);
}

/**
    @brief Run the whole show.

    @todo Handle signals properly.
*/
int main(
    int argc,
    char **argv)
{
    int ret = EXIT_SUCCESS;
    AnomalyDetector * anomaly_detector = NULL;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * pcap_handle = NULL;
    int pcap_loop_ret;

    OPEN_LOG();


    // Parse the command-line arguments.
    char const * filter = NULL;
    char const * interface = pcap_lookupdev(pcap_errbuf);

    static char const options[] = "f:hi:";
    static struct option const long_options[] = {
        {"filter", required_argument, NULL, 'f'},
        {"help", no_argument, NULL, 'h'},
        {"interface", required_argument, NULL, 'i'},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, options, long_options, NULL)) != -1)
    {
        switch (getopt_long(argc, argv, options, long_options, NULL))
        {
            case 'f':
                filter = optarg;
                break;

            case 'h':
                print_help();
                goto done;

            case 'i':
                interface = optarg;
                break;

            default:
                ret = EXIT_FAILURE;
                goto done;
        }
    }

    if (interface == NULL)
    {
        LOG(LOG_ERR,
            "A network interface was not specified and no default could be "
            "found. Please specify a network interface (-i).");
        ret = EXIT_FAILURE;
        goto done;
    }


    // Create initial state for the anomaly detector.
    try
    {
        anomaly_detector = new AnomalyDetector();
    }
    catch (std::bad_alloc & e)
    {
        LOG(LOG_ERR, "Error allocating memory for anomaly_detector");
        ret = EXIT_FAILURE;
        goto done;
    }


    // Prepare to sniff packets from the network.
    pcap_errbuf[0] = '\0';
    pcap_handle = pcap_open_live(interface, ANOMALY_SNAPLEN, 1,
        PCAP_READ_TIMEOUT, pcap_errbuf);
    if (pcap_handle == NULL)
    {
        LOG(LOG_ERR, "Error opening network interface %s: %s", interface,
            pcap_errbuf);
        ret = EXIT_FAILURE;
        goto done;
    }
    else if (pcap_errbuf[0] != '\0')
    {
        LOG(LOG_WARNING, "Warning opening network interface %s: %s", interface,
            pcap_errbuf);
    }

    if (filter != NULL)
    {
        struct bpf_program filter_compiled;
        if (pcap_compile(pcap_handle, &filter_compiled, filter, 1,
            PCAP_NETMASK_UNKNOWN) < 0)
        {
            LOG(LOG_ERR, "Error compiling pcap filter \"%s\": %s", filter,
                pcap_geterr(pcap_handle));
            ret = EXIT_FAILURE;
            goto done;
        }

        if (pcap_setfilter(pcap_handle, &filter_compiled) < 0)
        {
            LOG(LOG_ERR, "Error applying the pcap filter: %s",
                pcap_geterr(pcap_handle));
            ret = EXIT_FAILURE;
            goto done;
        }

        pcap_freecode(&filter_compiled);
    }


    // Sniff packets and run the anomaly detector.
    pcap_loop_ret = pcap_loop(pcap_handle, -1, packet_callback,
        (uint8_t *)anomaly_detector);
    if (pcap_loop_ret == -1)
    {
        LOG(LOG_ERR, "Error reading network traffic: %s",
            pcap_geterr(pcap_handle));
        ret = EXIT_FAILURE;
        goto done;
    }


done:
    // Perform cleanup and exit.
    if (pcap_handle != NULL)
    {
        pcap_close(pcap_handle);
    }

    if (anomaly_detector != NULL)
    {
        delete anomaly_detector;
    }

    CLOSE_LOG();

    return ret;
}
