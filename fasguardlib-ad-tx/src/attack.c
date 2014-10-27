// TODO: make the docs in this file internal-only

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include <fasguardlib-ad-tx.h>

#include "resources.h"


/**
    @brief Type pointed to by #fasguard_attack_output_t.
*/
struct fasguard_attack_output
{
    /**
        @brief Path for <tt>tmp/</tt>.
    */
    char * tmpdir;

    /**
        @brief Path for <tt>new/</tt>.
    */
    char * newdir;

    /**
        @brief Path for <tt>cur/</tt>.
    */
    char * curdir;
};

/**
    @brief Type pointed to by #fasguard_attack_group_t.
*/
struct fasguard_attack_group
{
    /**
        @brief Output stream to which this group belongs.
    */
    struct fasguard_attack_output * attack_output;

    /**
        @brief Path for <tt>tmp/<em>attack-group</em>/</tt>.
    */
    char * groupdir;

    /**
        @brief Path for <tt>tmp/<em>attack-group</em>/instances/</tt>.
    */
    char * instancesdir;

    /**
        @brief Path for <tt>tmp/<em>attack-group</em>/all.xml</tt>.
    */
    char * allpath;

    /**
        @brief File descriptor corresponding to #allpath.
    */
    int allfd;
};

struct fasguard_attack_instance
{
    /**
        @brief Group to which this instance belongs.
    */
    struct fasguard_attack_group * attack_group;

    /**
        @brief Path for
               <tt>tmp/<em>attack-group</em>/instances/<em>attack-instance</em></tt>.
    */
    char * instancepath;

    /**
        @brief File descriptor corresponding to #instancepath.
    */
    int instancefd;
};

/**
    @brief Return a string formatted as by printf(3).

    This function allocates a string long enough to fit the entire
    formmatted string, and returns it. The user is responsible for
    calling free() on this string. NULL is returned on error, and
    errno is set appropriately.
*/
static char * sprintf_alloc(
    char const * format,
    ...)
{
    va_list ap;

    va_start(ap, format);
    int length = vsnprintf(NULL, 0, format, ap);
    va_end(ap);

    char * s = malloc(length);
    if (s == NULL)
    {
        errno = ENOMEM;
        return NULL;
    }

    va_start(ap, format);
    vsnprintf(s, (size_t)length, format, ap);
    va_end(ap);

    return s;
}

fasguard_attack_output_t fasguard_open_attack_output(
    char const * directory,
    fasguard_option_t const * options)
{
    struct fasguard_attack_output * output = NULL;

    for (size_t i = 0;
        options != NULL && !FASGUARD_IS_END_OF_OPTIONS(options[i]);
        ++i)
    {
        switch (options[i].key)
        {
            default:
                errno = EINVAL;
                goto error;
        }
    }

    output = malloc(sizeof(struct fasguard_attack_output));
    if (output == NULL)
    {
        errno = ENOMEM;
        goto error;
    }

    output->tmpdir = NULL;
    output->newdir = NULL;
    output->curdir = NULL;

    if (mkdir(directory, 0700) == -1 && errno != EEXIST)
    {
        // errno set by mkdir()
        goto error;
    }

    output->tmpdir = sprintf_alloc("%s/tmp", directory);
    if (output->tmpdir == NULL)
    {
        // errno set by sprintf_alloc()
        goto error;
    }
    if (mkdir(output->tmpdir, 0700) == -1 && errno != EEXIST)
    {
        // errno set by mkdir()
        goto error;
    }

    output->newdir = sprintf_alloc("%s/new", directory);
    if (output->newdir == NULL)
    {
        // errno set by sprintf_alloc()
        goto error;
    }
    if (mkdir(output->newdir, 0700) == -1 && errno != EEXIST)
    {
        // errno set by mkdir()
        goto error;
    }

    output->curdir = sprintf_alloc("%s/cur", directory);
    if (output->curdir == NULL)
    {
        // errno set by sprintf_alloc()
        goto error;
    }
    if (mkdir(output->curdir, 0700) == -1 && errno != EEXIST)
    {
        // errno set by mkdir()
        goto error;
    }

    return output;

error:
    if (output != NULL)
    {
        free(output->tmpdir);
        free(output->newdir);
        free(output->curdir);
        free(output);
    }

    return NULL;
}

bool fasguard_flush_attack_output(
    fasguard_attack_output_t _output)
{
    (void)_output;
    return true;
}

bool fasguard_close_attack_output(
    fasguard_attack_output_t _output)
{
    struct fasguard_attack_output * output = (struct fasguard_attack_output *)_output;
    int last_errno = 0;

    if (output == NULL)
    {
        return true;
    }

    if (!fasguard_flush_attack_output(output))
    {
        last_errno = errno;
    }

    free(output->tmpdir);
    free(output->newdir);
    free(output->curdir);

    free(output);

    errno = last_errno;
    return errno == 0;
}

fasguard_attack_group_t fasguard_start_attack_group(
    fasguard_attack_output_t _output,
    fasguard_option_t const * options)
{
    struct fasguard_attack_output * output = (struct fasguard_attack_output *)_output;
    struct fasguard_attack_group * group = NULL;
    ssize_t written;

    for (size_t i = 0;
        options != NULL && !FASGUARD_IS_END_OF_OPTIONS(options[i]);
        ++i)
    {
        switch (options[i].key)
        {
            default:
                errno = EINVAL;
                return NULL;
        }
    }

    group = malloc(sizeof(struct fasguard_attack_group));
    if (group == NULL)
    {
        errno = ENOMEM;
        goto error;
    }

    group->attack_output = output;
    group->groupdir = NULL;
    group->instancesdir = NULL;
    group->allpath = NULL;
    group->allfd = -1;

    group->groupdir = sprintf_alloc("%s/XXXXXX", output->tmpdir);
    if (group->groupdir == NULL)
    {
        // errno set by sprintf_alloc()
        goto error;
    }
    if (mkdtemp(group->groupdir) == NULL)
    {
        // errno set by mkdtemp()
        goto error;
    }

    group->instancesdir = sprintf_alloc("%s/instances", group->groupdir);
    if (group->instancesdir == NULL)
    {
        // errno set by sprintf_alloc()
        goto error;
    }
    if (mkdir(group->instancesdir, 0700) == -1)
    {
        // errno set by mkdir()
        goto error;
    }

    group->allpath = sprintf_alloc("%s/all.xml", group->groupdir);
    if (group->allpath == NULL)
    {
        // errno set by sprintf_alloc()
        goto error;
    }
    group->allfd = open(group->allpath, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (group->allfd == -1)
    {
        // errno set by open()
        goto error;
    }

    written = write(group->allfd, fasguard_stix_package_header,
        fasguard_stix_package_header_strlen);
    if (written < 0)
    {
        // errno set by write()
        goto error;
    }
    else if ((size_t)written != fasguard_stix_package_header_strlen)
    {
        errno = EIO;
        goto error;
    }

    return group;

error:
    // The following code ignores the return values of close() because we're
    // already reporting an error. Note that close() changes errno if it fails.

    if (group != NULL)
    {
        free(group->groupdir);
        free(group->instancesdir);
        free(group->allpath);

        if (group->allfd >= 0)
        {
            close(group->allfd);
        }

        free(group);
    }

    return NULL;
}

bool fasguard_end_attack_group(
    fasguard_attack_group_t _group)
{
    struct fasguard_attack_group * group = (struct fasguard_attack_group *)_group;
    int last_errno = 0;
    ssize_t written;

    if (group == NULL)
    {
        return true;
    }

    written = write(group->allfd, fasguard_stix_package_footer,
        fasguard_stix_package_footer_strlen);
    if (written < 0)
    {
        last_errno = errno;
    }
    else if ((size_t)written != fasguard_stix_package_footer_strlen)
    {
        last_errno = EIO;
    }

    if (close(group->allfd) == -1)
    {
        last_errno = errno;
    }

    // TODO: move group->allpath into group->attack_output->newdir
    free(group->allpath);

    // TODO: rmdir group->instancesdir
    free(group->instancesdir);

    // TODO: rmdir group->groupdir
    free(group->groupdir);

    free(group);

    errno = last_errno;
    return errno == 0;
}

fasguard_attack_instance_t fasguard_start_attack_instance(
    fasguard_attack_group_t _group,
    fasguard_option_t const * options)
{
    struct fasguard_attack_group * group = (struct fasguard_attack_group *)_group;
    struct fasguard_attack_instance * instance = NULL;

    for (size_t i = 0;
        options != NULL && !FASGUARD_IS_END_OF_OPTIONS(options[i]);
        ++i)
    {
        switch (options[i].key)
        {
            default:
                errno = EINVAL;
                return NULL;
        }
    }

    instance = malloc(sizeof(struct fasguard_attack_instance));
    if (instance == NULL)
    {
        errno = ENOMEM;
        goto error;
    }

    instance->attack_group = group;
    instance->instancepath = NULL;
    instance->instancefd = -1;

    instance->instancepath =
        sprintf_alloc("%s/XXXXXX", group->instancesdir);
    if (instance->instancepath == NULL)
    {
        // errno set by sprintf_alloc()
        goto error;
    }
    instance->instancefd = mkstemp(instance->instancepath);
    if (instance->instancefd == -1)
    {
        // errno set by mkstemp()
        goto error;
    }

    return instance;

error:
    // The following code ignores the return values of close() because we're
    // already reporting an error. Note that close() changes errno if it fails.

    if (instance != NULL)
    {
        free(instance->instancepath);

        if (instance->instancefd >= 0)
        {
            close(instance->instancefd);
        }

        free(instance);
    }

    return NULL;
}

bool fasguard_end_attack_instance(
    fasguard_attack_instance_t _instance)
{
    struct fasguard_attack_instance * instance =
        (struct fasguard_attack_instance *)_instance;
    int last_errno = 0;
    ssize_t written;

    if (instance == NULL)
    {
        return true;
    }

    written = write(instance->attack_group->allfd,
        fasguard_stix_incident_header,
        fasguard_stix_incident_header_strlen);
    if (written < 0)
    {
        last_errno = errno;
        goto done_writing;
    }
    else if ((size_t)written != fasguard_stix_incident_header_strlen)
    {
        last_errno = EIO;
        goto done_writing;
    }

    // TODO: rewind instance->instancefd
    // TODO: copy all of instance->instancefd to instance->attack_group->allfd

    written = write(instance->attack_group->allfd,
        fasguard_stix_incident_footer,
        fasguard_stix_incident_footer_strlen);
    if (written < 0)
    {
        last_errno = errno;
        goto done_writing;
    }
    else if ((size_t)written != fasguard_stix_incident_footer_strlen)
    {
        last_errno = EIO;
        goto done_writing;
    }

done_writing:
    if (close(instance->instancefd) == -1)
    {
        last_errno = errno;
    }

    // TODO: unlink instance->instancepath
    free(instance->instancepath);

    free(instance);

    errno = last_errno;
    return errno == 0;
}

bool add_packet_to_attack_instance(
    fasguard_attack_instance_t _instance,
    size_t packet_length,
    uint8_t const * packet,
    fasguard_option_t const * options)
{
    struct fasguard_attack_instance * instance =
        (struct fasguard_attack_instance *)_instance;
    ssize_t written;

    for (size_t i = 0;
        options != NULL && !FASGUARD_IS_END_OF_OPTIONS(options[i]);
        ++i)
    {
        switch (options[i].key)
        {
            default:
                errno = EINVAL;
                return NULL;
        }
    }

    written = write(instance->instancefd, fasguard_stix_packet_header,
        fasguard_stix_packet_header_strlen);
    if (written < 0)
    {
        // errno set by write()
        return false;
    }
    else if ((size_t)written != fasguard_stix_packet_header_strlen)
    {
        errno = EIO;
        return false;
    }

    // TODO: support probability of attack (fasguard_stix_packet_prob_attack_fmt)

    // TODO: support timestamp of packet (fasguard_stix_packet_timestamp_timefmt)

    written = write(instance->instancefd, fasguard_stix_packet_data_header,
        fasguard_stix_packet_data_header_strlen);
    if (written < 0)
    {
        // errno set by write()
        return false;
    }
    else if ((size_t)written != fasguard_stix_packet_data_header_strlen)
    {
        errno = EIO;
        return false;
    }

    // TODO: write Base64 of packet data
    (void)packet_length;
    (void)packet;

    written = write(instance->instancefd, fasguard_stix_packet_data_footer,
        fasguard_stix_packet_data_footer_strlen);
    if (written < 0)
    {
        // errno set by write()
        return false;
    }
    else if ((size_t)written != fasguard_stix_packet_data_footer_strlen)
    {
        errno = EIO;
        return false;
    }

    written = write(instance->instancefd, fasguard_stix_packet_footer,
        fasguard_stix_packet_footer_strlen);
    if (written < 0)
    {
        // errno set by write()
        return false;
    }
    else if ((size_t)written != fasguard_stix_packet_footer_strlen)
    {
        errno = EIO;
        return false;
    }

    return true;
}
