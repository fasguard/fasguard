/**
    @file

    @todo Provide real implementations instead of stubs in this file.
*/

#include <stdlib.h>

#include "anomaly.h"
#include "logging.h"


/**
    @brief This struct contains all the state for the anomaly detector.
*/
struct anomaly_data
{
    uint8_t ignored;
};


void * new_anomaly_data()
{
    struct anomaly_data * data = malloc(sizeof(struct anomaly_data));
    if (data == NULL)
    {
        LOG(LOG_ERR, "Error allocating anomaly data.");
        return NULL;
    }

    // TODO: initialize contents of data

    return data;
}

void free_anomaly_data(
    void * data)
{
    if (data == NULL)
    {
        return;
    }

    struct anomaly_data * anomaly_data = (struct anomaly_data *)data;

    // TODO: free contents of anomaly_data

    free(anomaly_data);

    return;
}

void anomaly_packet_callback(
    uint8_t * user,
    struct pcap_pkthdr const * h,
    uint8_t const * bytes)
{
    struct anomaly_data * data = (struct anomaly_data *)user;

    (void)data;
    (void)h;
    (void)bytes;
}
