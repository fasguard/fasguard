/**
    @file
    @brief Main code for the host-peering anomaly detector.
*/

#include <cstdio>
#include <cstdlib>
#include <getopt.h>
#include <new>
#include <pcap/pcap.h>

#include "anomaly.hpp"
#include "linkheader.hpp"
#include "logging.hpp"


/**
    @brief Read timeout (in milliseconds) for pcap_open_live.
*/
#define PCAP_READ_TIMEOUT 1000


/**
    @brief Print a help message.
*/
static void print_help(
    int argc,
    char **argv,
    char const * default_interface)
{
    (void)argc;

    fprintf(stderr, "Usage: %s [<option>...]\n", argv[0]);
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr,
        "\t-f | --filter <filter>\tFilter traffic before processing.\n"
        "\t\tSee pcap-filter(7) for the format of the filter.\n"
        "\t\tDefault: none.\n");
    fprintf(stderr,
        "\t-h | --help\tPrint this help message.\n");
    fprintf(stderr,
        "\t-i | --interface <interface>\tSpecify the interface to listen on.\n");
    if (default_interface != NULL)
    {
        fprintf(stderr, "\t\tDefault: %s.\n", default_interface);
    }
    fprintf(stderr,
        "\t-r | --read <savefile>\tSpecify the pcap savefile to read from.\n");
    if (default_interface == NULL)
    {
        fprintf(stderr, "\n");
        fprintf(stderr, "Either --interface or --read must be specified.\n");
    }
}

/**
    @brief Data to pass to #packet_callback.
*/
struct packet_callback_data_t
{
    /** @brief Callback to get the layer 2 header length. */
    layer2_hlen_t layer2_hlen_callback;

    /** @brief Anomaly detector. */
    AnomalyDetector * anomaly_detector;
};

/**
    @brief Handle a single packet.

    This function is suitable for passing as the callback to pcap_loop.
*/
static void packet_callback(
    uint8_t * user,
    struct pcap_pkthdr const * h,
    uint8_t const * bytes)
{
    packet_callback_data_t * packet_callback_data =
        (packet_callback_data_t *)user;

    size_t layer2_hlen = packet_callback_data->layer2_hlen_callback(
        h->caplen, bytes);

    packet_callback_data->anomaly_detector->process_packet(
        h, layer2_hlen, bytes);
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
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * pcap_handle = NULL;
    int link_layer_header_type;
    packet_callback_data_t packet_callback_data = {
        .layer2_hlen_callback = NULL,
        .anomaly_detector = NULL,
    };
    int pcap_loop_ret;

    OPEN_LOG();


    // Parse the command-line arguments.
    char const * filter = NULL;
    char const * default_interface = pcap_lookupdev(pcap_errbuf);
    char const * interface = default_interface;
    char const * savefile = NULL;

    static char const options[] = "f:hi:r:";
    static struct option const long_options[] = {
        {"filter", required_argument, NULL, 'f'},
        {"help", no_argument, NULL, 'h'},
        {"interface", required_argument, NULL, 'i'},
        {"read", required_argument, NULL, 'r'},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, options, long_options, NULL)) != -1)
    {
        switch (opt)
        {
            case 'f':
                filter = optarg;
                break;

            case 'h':
                print_help(argc, argv, default_interface);
                goto done;

            case 'i':
                interface = optarg;
                break;

            case 'r':
                savefile = optarg;
                break;

            default:
                ret = EXIT_FAILURE;
                goto done;
        }
    }

    if (interface == NULL && savefile == NULL)
    {
        LOG(LOG_ERR,
            "Neither a network interface nor a pcap savefile was specified, "
            "and no default could be found. Please specify a network interface "
            "(-i) or savefile (-r).");
        ret = EXIT_FAILURE;
        goto done;
    }
    else if (interface != NULL && savefile != NULL)
    {
        LOG(LOG_ERR, "Please only specify one of -i or -r.");
        ret = EXIT_FAILURE;
        goto done;
    }


    // Prepare to sniff packets from the network.
    pcap_errbuf[0] = '\0';
    if (savefile != NULL)
    {
        pcap_handle = pcap_open_offline(savefile, pcap_errbuf);

        if (pcap_handle == NULL)
        {
            LOG(LOG_ERR, "Error opening pcap savefile \"%s\": %s", savefile,
                pcap_errbuf);
            ret = EXIT_FAILURE;
            goto done;
        }
    }
    else
    {
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

    link_layer_header_type = pcap_datalink(pcap_handle);
    switch (link_layer_header_type)
    {
        case DLT_EN10MB:
            packet_callback_data.layer2_hlen_callback = layer2_hlen_ethernet;
            break;

        default:
            LOG(LOG_ERR, "Unsupported linktype with value %d",
                link_layer_header_type);
            ret = EXIT_FAILURE;
            goto done;
    }


    // Create initial state for the anomaly detector.
    try
    {
        packet_callback_data.anomaly_detector = new AnomalyDetector();
    }
    catch (std::bad_alloc & e)
    {
        LOG(LOG_ERR, "Error allocating memory for anomaly_detector");
        ret = EXIT_FAILURE;
        goto done;
    }


    // Sniff packets and run the anomaly detector.
    pcap_loop_ret = pcap_loop(pcap_handle, -1, packet_callback,
        (uint8_t *)&packet_callback_data);
    if (pcap_loop_ret == -1)
    {
        LOG(LOG_ERR, "Error reading network traffic: %s",
            pcap_geterr(pcap_handle));
        ret = EXIT_FAILURE;
        goto done;
    }
    else if (pcap_loop_ret == 0)
    {
        LOG(LOG_DEBUG, "No more packets to read.");
    }


done:
    // Perform cleanup and exit.
    if (packet_callback_data.anomaly_detector != NULL)
    {
        delete packet_callback_data.anomaly_detector;
    }

    if (pcap_handle != NULL)
    {
        pcap_close(pcap_handle);
    }

    CLOSE_LOG();

    return ret;
}
