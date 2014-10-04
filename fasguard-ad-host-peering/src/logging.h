#ifndef _HOST_PEERING_LOGGING_H
#define _HOST_PEERING_LOGGING_H

#include <syslog.h>
#include <stdbool.h>

/**
    Open the log for writing.

    This should be called before any calls to #LOG().
*/
#define OPEN_LOG() \
    do \
    { \
        openlog(PACKAGE_NAME, LOG_PID | LOG_PERROR, LOG_USER); \
    } while (false)

/**
    Close the log.

    This should be called before the program exits.
*/
#define CLOSE_LOG() \
    do \
    { \
        closelog(); \
    } while (false)

/**
    Log a message.
*/
#define LOG(priority, format, ...) \
    do \
    { \
        syslog((priority), (format), ## __VA_ARGS__); \
    } while (false)

#endif
