/**
    @file
    @brief Main code for the host-peering anomaly detector.
*/

#include <cstdio>
#include <cstdlib>
#include <getopt.h>
#include <new>
#include <pcap/pcap.h>
#include <unordered_map>

#include <fasguardlib-ad-tx.h>

#include "anomaly.hpp"
#include "linkheader.hpp"
#include "logging.hpp"
#include "network.hpp"


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
    fprintf(stderr,
        "\t-o | --output <directory>\tDirectory to write STIX files to.\n"
        "\t\tThis option is mandatory.\n");
    if (default_interface == NULL)
    {
        fprintf(stderr, "\n");
        fprintf(stderr, "Either --interface or --read must be specified.\n");
    }
}

/**
    @brief Data for a single attack group.
*/
struct attack_group_data_t
{
    /**
        @brief Handle for the group.
    */
    fasguard_attack_group_t group;

    /**
        @brief Map from IP to attack instance.
    */
    std::unordered_map<IPAddress, fasguard_attack_instance_t> instances;
};

/**
    @brief Data to pass to #packet_callback.
*/
struct packet_callback_data_t
{
    /**
        @brief Initialize values to their defaults.
    */
    packet_callback_data_t()
    :
        pcap_handle(NULL),
        error(false),
        layer2_hlen_callback(NULL),
        anomaly_detector(NULL),
        attack_output(NULL),
        attack_groups()
    {
    }

    /**
        @brief Pcap handle.
    */
    pcap_t * pcap_handle;

    /**
        @brief Whether or not there was an error while processing
               packets.
    */
    bool error;

    /** @brief Callback to get the layer 2 header length. */
    layer2_hlen_t layer2_hlen_callback;

    /** @brief Anomaly detector. */
    AnomalyDetector * anomaly_detector;

    /**
        @brief Handle for attack output stream.
    */
    fasguard_attack_output_t attack_output;

    /**
        @brief Map from IP to attack group.
    */
    std::unordered_map<IPAddress, attack_group_data_t> attack_groups;

};

/**
    @brief Handle a potential attack from @p ip1 to @p ip2.

    Manage attack group and attack instance handles, and add the
    packet to the appropriate attack instance if @p ip1 appears
    to be attacking @p ip2.
*/
static void handle_attacks(
    packet_callback_data_t * packet_callback_data,
    IPAddress const & ip1,
    IPAddress const & ip2,
    struct pcap_pkthdr const * pcap_header,
    size_t layer2_hlen,
    uint8_t const * packet)
{
    bool const anomalous =
        packet_callback_data->anomaly_detector->is_anomalous(ip1);

    attack_group_data_t * group = NULL;
    auto group_it = packet_callback_data->attack_groups.find(ip1);
    if (group_it != packet_callback_data->attack_groups.end())
    {
        group = &group_it->second;

        if (!anomalous)
        {
            for (auto instance_pair : group->instances)
            {
                if (!fasguard_end_attack_instance(instance_pair.second))
                {
                    LOG_PERROR_R(LOG_ERR,
                        "Could not end attack instance %s -> %s",
                        group_it->first.toString().c_str(),
                        instance_pair.first.toString().c_str());

                    packet_callback_data->error = true;
                    pcap_breakloop(packet_callback_data->pcap_handle);
                }
            }
            group->instances.clear();

            if (!fasguard_end_attack_group(group->group))
            {
                LOG_PERROR_R(LOG_ERR,
                    "Could not end attack group %s",
                    group_it->first.toString().c_str());

                packet_callback_data->error = true;
                pcap_breakloop(packet_callback_data->pcap_handle);
            }

            packet_callback_data->attack_groups.erase(group_it);

            return;
        }
    }
    else
    {
        if (!anomalous)
        {
            return;
        }

        group = &packet_callback_data->attack_groups[ip1];
        group->group = fasguard_start_attack_group(
            packet_callback_data->attack_output,
            NULL);
        if (group->group == NULL)
        {
            LOG_PERROR_R(LOG_WARNING,
                "Could not start attack group %s",
                ip1.toString().c_str());

            packet_callback_data->attack_groups.erase(ip1);

            return;
        }
    }

    fasguard_attack_instance_t instance = NULL;
    auto instance_it = group->instances.find(ip2);
    if (instance_it != group->instances.end())
    {
        instance = &instance_it->second;
    }
    else
    {
        instance = fasguard_start_attack_instance(
            group->group,
            NULL);
        if (instance == NULL)
        {
            LOG_PERROR_R(LOG_WARNING,
                "Could not start attack instance %s -> %s",
                ip1.toString().c_str(),
                ip2.toString().c_str());

            return;
        }

        group->instances[ip2] = instance;
    }

    if (!fasguard_add_packet_to_attack_instance(
        instance,
        pcap_header->caplen - layer2_hlen,
        packet + layer2_hlen,
        NULL))
    {
        LOG_PERROR_R(LOG_WARNING,
            "Could not add packet to attack instance %s -> %s",
            ip1.toString().c_str(),
            ip2.toString().c_str());
    }
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
    packet_callback_data_t * packet_callback_data =
        (packet_callback_data_t *)user;

    size_t layer2_hlen = packet_callback_data->layer2_hlen_callback(
        h->caplen, bytes);

    packet_callback_data->anomaly_detector->process_packet(
        h, layer2_hlen, bytes);

    IPAddress srcAddress;
    IPAddress dstAddress;
    if (IPAddress::parse_packet(
        srcAddress, dstAddress,
        h->caplen - layer2_hlen, bytes + layer2_hlen))
    {
        handle_attacks(
            packet_callback_data,
            srcAddress, dstAddress,
            h, layer2_hlen, bytes);
        handle_attacks(
            packet_callback_data,
            dstAddress, srcAddress,
            h, layer2_hlen, bytes);
    }
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
    int link_layer_header_type;
    packet_callback_data_t packet_callback_data;
    int pcap_loop_ret;

    OPEN_LOG();


    // Parse the command-line arguments.
    char const * filter = NULL;
    char const * default_interface = pcap_lookupdev(pcap_errbuf);
    char const * interface = default_interface;
    char const * output_directory = NULL;
    char const * savefile = NULL;

    static char const options[] = "f:hi:o:r:";
    static struct option const long_options[] = {
        {"filter", required_argument, NULL, 'f'},
        {"help", no_argument, NULL, 'h'},
        {"interface", required_argument, NULL, 'i'},
        {"output", required_argument, NULL, 'o'},
        {"read", required_argument, NULL, 'r'},
        {NULL, 0, NULL, 0},
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

            case 'o':
                output_directory = optarg;
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
    else if (output_directory == NULL)
    {
        LOG(LOG_ERR, "An output directory (-o) must be specified.");
        ret = EXIT_FAILURE;
        goto done;
    }


    // Prepare to sniff packets from the network.
    pcap_errbuf[0] = '\0';
    if (savefile != NULL)
    {
        packet_callback_data.pcap_handle =
            pcap_open_offline(savefile, pcap_errbuf);

        if (packet_callback_data.pcap_handle == NULL)
        {
            LOG(LOG_ERR, "Error opening pcap savefile \"%s\": %s", savefile,
                pcap_errbuf);
            ret = EXIT_FAILURE;
            goto done;
        }
    }
    else
    {
        packet_callback_data.pcap_handle = pcap_open_live(
            interface, ANOMALY_SNAPLEN, 1,
            PCAP_READ_TIMEOUT, pcap_errbuf);

        if (packet_callback_data.pcap_handle == NULL)
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
        if (pcap_compile(packet_callback_data.pcap_handle,
            &filter_compiled, filter, 1, PCAP_NETMASK_UNKNOWN) < 0)
        {
            LOG(LOG_ERR, "Error compiling pcap filter \"%s\": %s", filter,
                pcap_geterr(packet_callback_data.pcap_handle));
            ret = EXIT_FAILURE;
            goto done;
        }

        if (pcap_setfilter(packet_callback_data.pcap_handle,
            &filter_compiled) < 0)
        {
            LOG(LOG_ERR, "Error applying the pcap filter: %s",
                pcap_geterr(packet_callback_data.pcap_handle));
            ret = EXIT_FAILURE;
            goto done;
        }

        pcap_freecode(&filter_compiled);
    }

    link_layer_header_type =
        pcap_datalink(packet_callback_data.pcap_handle);
    switch (link_layer_header_type)
    {
        case DLT_EN10MB:
            packet_callback_data.layer2_hlen_callback = layer2_hlen_ethernet;
            break;

        case DLT_RAW:
            packet_callback_data.layer2_hlen_callback = layer2_hlen_raw;
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


    // Open the output stream.
    packet_callback_data.attack_output = fasguard_open_attack_output(
        output_directory, NULL);
    if (packet_callback_data.attack_output == NULL)
    {
        LOG_PERROR_R(LOG_ERR,
            "Error opening attack output directory %s",
            output_directory);
        ret = EXIT_FAILURE;
        goto done;
    }


    // Sniff packets and run the anomaly detector.
    pcap_loop_ret = pcap_loop(packet_callback_data.pcap_handle, -1,
        packet_callback, (uint8_t *)&packet_callback_data);
    if (pcap_loop_ret == -1)
    {
        LOG(LOG_ERR, "Error reading network traffic: %s",
            pcap_geterr(packet_callback_data.pcap_handle));
        ret = EXIT_FAILURE;
        goto done;
    }
    else if (pcap_loop_ret == 0)
    {
        LOG(LOG_DEBUG, "No more packets to read.");
    }
    else if (packet_callback_data.error)
    {
        ret = EXIT_FAILURE;
    }


done:
    // Perform cleanup and exit.
    if (packet_callback_data.anomaly_detector != NULL)
    {
        delete packet_callback_data.anomaly_detector;
    }

    for (auto group_pair : packet_callback_data.attack_groups)
    {
        for (auto instance_pair : group_pair.second.instances)
        {
            if (!fasguard_end_attack_instance(instance_pair.second))
            {
                LOG_PERROR_R(LOG_ERR,
                    "Could not end attack instance %s -> %s",
                    group_pair.first.toString().c_str(),
                    instance_pair.first.toString().c_str());
                ret = EXIT_FAILURE;
            }
        }
        group_pair.second.instances.clear();

        if (!fasguard_end_attack_group(group_pair.second.group))
        {
            LOG_PERROR_R(LOG_ERR,
                "Could not end attack group %s",
                group_pair.first.toString().c_str());
            ret = EXIT_FAILURE;
        }
    }
    packet_callback_data.attack_groups.clear();

    if (packet_callback_data.attack_output != NULL)
    {
        if (!fasguard_close_attack_output(
            packet_callback_data.attack_output))
        {
            LOG_PERROR_R(LOG_ERR,
                "Error closing attack output directory");
            ret = EXIT_FAILURE;
        }
    }

    if (packet_callback_data.pcap_handle != NULL)
    {
        pcap_close(packet_callback_data.pcap_handle);
    }

    CLOSE_LOG();

    return ret;
}
