/**
    @cond INTERNAL
    @file
    @brief Implement the attack output stream.
*/

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include <fasguardlib-ad-tx.h>

#include "macros.h"
#include "resources.h"


/**
    @brief Length of a serialized UUID, in characters.

    @note This does not include the terminating NUL byte.
*/
#define UUID_CHAR_LENGTH 36


/**
    @brief Type pointed to by #fasguard_attack_output_type.
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
    @brief Type pointed to by #fasguard_attack_group_type.
*/
struct fasguard_attack_group
{
    /**
        @brief Output stream to which this group belongs.
    */
    struct fasguard_attack_output * attack_output;

    /**
        @brief ID of the attack group.
    */
    uuid_t id;

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

    /**
        @brief Path for <tt>new/<em>attack-group</em>.xml</tt>.
    */
    char * alldonepath;
};

/**
    @brief Type pointed to by #fasguard_attack_instance_type.
*/
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
    FORMAT_PRINTF(1, 2);

static char * sprintf_alloc(
    char const * format,
    ...)
{
    va_list ap;

    va_start(ap, format);
    int length = vsnprintf(NULL, 0, format, ap) + 1;
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

/**
    @brief Write Base64-encoded data to a file descriptor.

    @todo Provide a more efficient implementation of this, i.e., one
          that doesn't do all writes in increments of one byte.

    @param[in] fd File descriptor to write to.
    @param[in] buf Buffer to write from.
    @param[in] count Lenth of @p buf.
    @return True on success, or false on error. If false is returned,
            errno will be set appropriately.
*/
static bool write_b64(
    int fd,
    uint8_t const * buf,
    size_t count)
{
    static char const * const b64_alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456798+/";
    static char const b64_padding = '=';
    static size_t const b64_line_length = 64;
    static char const b64_eol = '\n';

    // Sliding window of bits from buf. More-significant bits appeared
    // earlier in buf than less-significant bits. Only the
    // least-significant bits of bitbuffer are used.
    uint_fast16_t bitbuffer;

    // Number of least-significant bits in bitbuffer that have been
    // set, including for padding purposes.
    uint_fast8_t bits = 0;

    // Number of least significant bits in bitbuffer that have been
    // set to zero for padding purposes.
    uint_fast8_t fakebits = 0;

    // Length of the current line.
    size_t current_line_length = 0;

    char const * to_write;
    ssize_t written;

    for (size_t i = 0;
        i < count || bits > 0;
        ++i)
    {
        if (i < count)
        {
            bitbuffer = (bitbuffer << 8) | buf[i];
            bits += 8;
        }
        else
        {
            bitbuffer = bitbuffer << 8;
            bits += 8;
            fakebits += 8;
        }

        while (bits >= 6)
        {
            if (bits > fakebits)
            {
                to_write =
                    &b64_alphabet[(bitbuffer >> (bits - 6)) & 0x3f];
            }
            else
            {
                to_write = &b64_padding;
            }

            written = write(fd, to_write, 1);
            if (written < 0)
            {
                // errno set by write()
                return false;
            }
            else if (written != 1)
            {
                errno = EIO;
                return false;
            }
            ++current_line_length;

            if (b64_line_length > 0 &&
                current_line_length >= b64_line_length)
            {
                written = write(fd, &b64_eol, 1);
                if (written < 0)
                {
                    // errno set by write()
                    return false;
                }
                else if (written != 1)
                {
                    errno = EIO;
                    return false;
                }

                current_line_length = 0;
            }

            bits -= 6;
            if (fakebits > bits)
            {
                fakebits = bits;
            }
        }
    }

    // End the last line, if line wrapping is enabled and the last
    // line was not already ended.
    if (b64_line_length > 0 && current_line_length > 0)
    {
        written = write(fd, &b64_eol, 1);
        if (written < 0)
        {
            // errno set by write()
            return false;
        }
        else if (written != 1)
        {
            errno = EIO;
            return false;
        }

        current_line_length = 0;
    }

    return true;
}

fasguard_attack_output_type fasguard_open_attack_output(
    char const * directory,
    fasguard_option_type const * options)
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
    fasguard_attack_output_type _output)
{
    (void)_output;
    return true;
}

bool fasguard_close_attack_output(
    fasguard_attack_output_type _output)
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

fasguard_attack_group_type fasguard_start_attack_group(
    fasguard_attack_output_type _output,
    fasguard_option_type const * options)
{
    struct fasguard_attack_output * output = (struct fasguard_attack_output *)_output;
    struct fasguard_attack_group * group = NULL;
    char id_str[UUID_CHAR_LENGTH + 1];
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
    group->alldonepath = NULL;

    uuid_generate(group->id);
    uuid_unparse(group->id, id_str);

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

    group->alldonepath = sprintf_alloc("%s/%s.xml", output->newdir,
        id_str);
    if (group->alldonepath == NULL)
    {
        // errno set by sprintf_alloc()
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

        free(group->alldonepath);

        free(group);
    }

    return NULL;
}

bool fasguard_end_attack_group(
    fasguard_attack_group_type _group)
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

    if (rename(group->allpath, group->alldonepath) == -1)
    {
        last_errno = errno;
    }
    free(group->allpath);
    free(group->alldonepath);

    if (rmdir(group->instancesdir) == -1)
    {
        last_errno = errno;
    }
    free(group->instancesdir);

    if (rmdir(group->groupdir) == -1)
    {
        last_errno = errno;
    }
    free(group->groupdir);

    free(group);

    errno = last_errno;
    return errno == 0;
}

fasguard_attack_instance_type fasguard_start_attack_instance(
    fasguard_attack_group_type _group,
    fasguard_option_type const * options)
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
    fasguard_attack_instance_type _instance)
{
    struct fasguard_attack_instance * instance =
        (struct fasguard_attack_instance *)_instance;
    int last_errno = 0;
    uint8_t buf[512];
    ssize_t readed; // bad grammar to avoid name clash
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

    if (lseek(instance->instancefd, 0, SEEK_SET) == -1)
    {
        last_errno = errno;
        goto done_writing;
    }

    // copy all of instance->instancefd to instance->attack_group->allfd
    while ((readed = read(instance->instancefd, buf, sizeof(buf))) != 0)
    {
        if (readed < 0)
        {
            last_errno = errno;
            goto done_writing;
        }

        written = write(instance->attack_group->allfd, buf,
            (size_t)readed);
        if (written < 0)
        {
            last_errno = errno;
            goto done_writing;
        }
        else if (written != readed)
        {
            last_errno = EIO;
            goto done_writing;
        }
    }

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

    if (unlink(instance->instancepath) == -1)
    {
        last_errno = errno;
    }
    free(instance->instancepath);

    free(instance);

    errno = last_errno;
    return errno == 0;
}

bool fasguard_add_packet_to_attack_instance(
    fasguard_attack_instance_type _instance,
    size_t packet_length,
    uint8_t const * packet,
    fasguard_option_type const * options)
{
    struct fasguard_attack_instance * instance =
        (struct fasguard_attack_instance *)_instance;
    struct timeval const * timestamp = NULL;
    double probability_attack = -1.0;
    ssize_t written;

    for (size_t i = 0;
        options != NULL && !FASGUARD_IS_END_OF_OPTIONS(options[i]);
        ++i)
    {
        switch (options[i].key)
        {
            case FASGUARD_OPTION_TIMESTAMP:
                timestamp = options[i].value.pointer_val;
                break;

            case FASGUARD_OPTION_PROBABILITY_MALICIOUS:
                probability_attack = options[i].value.double_val;
                break;

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

    if (probability_attack >= 0.0 && probability_attack <= 1.0)
    {
        char * probability_attack_str = sprintf_alloc(
            (char const *)fasguard_stix_packet_prob_attack_fmt,
            probability_attack);
        if (probability_attack_str == NULL)
        {
            // errno set by sprintf_alloc()
            return false;
        }

        size_t const probability_attack_strlen =
            strlen(probability_attack_str);

        written = write(instance->instancefd, probability_attack_str,
            probability_attack_strlen);
        int errno_save = errno;

        free(probability_attack_str);

        if (written < 0)
        {
            errno = errno_save;
            return false;
        }
        else if ((size_t)written != probability_attack_strlen)
        {
            errno = EIO;
            return false;
        }
    }

    if (timestamp != NULL)
    {
        // TODO: include timestamp->tv_usec in the XML

        struct tm timestamp_tm;
        gmtime_r(&timestamp->tv_sec, &timestamp_tm);

        // There doesn't seem like a good way to get the correct
        // length ahead of time, but this should work as a rough
        // over-estimate.
        size_t const timestamp_len =
            fasguard_stix_packet_timestamp_timefmt_strlen + 128;
        char * timestamp_str = malloc(timestamp_len);
        if (timestamp_str == NULL)
        {
            errno = ENOMEM;
            return false;
        }

        size_t const timestamp_strlen = strftime(
            timestamp_str, timestamp_len,
            (char const *)fasguard_stix_packet_timestamp_timefmt,
            &timestamp_tm);
        if (timestamp_strlen == 0)
        {
            // timestamp_len was too small
            free(timestamp_str);
            errno = EINVAL;
            return false;
        }

        written = write(instance->instancefd, timestamp_str,
            timestamp_strlen);
        int errno_save = errno;

        free(timestamp_str);

        if (written < 0)
        {
            errno = errno_save;
            return false;
        }
        else if ((size_t)written != timestamp_strlen)
        {
            errno = EIO;
            return false;
        }
    }

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

    if (!write_b64(instance->instancefd, packet, packet_length))
    {
        // errno set by write_b64()
        return false;
    }

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

/**
    @endcond
*/
