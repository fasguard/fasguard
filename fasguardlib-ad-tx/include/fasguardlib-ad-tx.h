/**
    @file
    @brief Header file for libfasguardlib-ad-tx.
*/

#ifndef FASGUARDLIB_AD_TX_H
#define FASGUARDLIB_AD_TX_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>


/**
    @brief Container for any option value.

    This is meant to store the value for any single option. Each option will
    specify how this value is used.
*/
typedef union
{
    /**
        @brief Boolean value.
    */
    bool bool_val;

    /**
       @brief Unsigned integer value.
    */
    uintmax_t uint_val;

    /**
        @brief Integer value.
    */
    intmax_t int_val;

    /**
        @brief Double value.
    */
    double double_val;

    /**
        @brief Pointer value.

        @note The memory pointed to is the responsibility of the caller, not of
              the library. If you allocated it, you free it.
    */
    void const * pointer_val;
} fasguard_option_value_type;

/**
    @brief Store a single option.

    Various functions below take a parameter of type
    <tt>#fasguard_option_type const *</tt>, which is a pointer to an array of
    key-value options. The array of options must end with the special
    value #fasguard_end_of_options. If the pointer is NULL, it is treated
    the same as an array containing only #fasguard_end_of_options.
*/
typedef struct
{
    /**
        @brief Set of flags for the option.

        There are currently no public flags, so this must be zero for all
        options defined outside of this library. When defined, option flags
        will start with FASGUARD_OPTFLAG_.
    */
    uint32_t flags;

    /**
        @brief Reserved for future use.

        This must be set to zero.
    */
    uint16_t reserved;

    /**
        @brief Key for the option.

        This must be a valid option key (starting with FASGUARD_OPTION_).
    */
    uint16_t key;

    /**
        @brief Value for the option.

        The interpretation of this value depends on the #key.
    */
    fasguard_option_value_type value;
} fasguard_option_type;

/**
    @internal
    @brief Special flag to indicate the end of an array of fasguard_option_type.
*/
#define FASGUARD_OPTFLAG_END_OF_OPTIONS UINT32_C(0x80000000)

/**
    @brief Special value to indicate the end of an array of #fasguard_option_type.
*/
extern fasguard_option_type const fasguard_end_of_options;

/**
    @internal
    @brief Determine if an option (of type #fasguard_option_type) is
           #fasguard_end_of_options.
*/
#define FASGUARD_IS_END_OF_OPTIONS(option) \
    ((option).flags & FASGUARD_OPTFLAG_END_OF_OPTIONS)

/**
    @brief Timestamp to microsecond precision.

    #fasguard_option_value_type::pointer_val will contain a non-NULL pointer
    to a struct timeval.
*/
#define FASGUARD_OPTION_TIMESTAMP UINT16_C(0x0001)

/**
    @brief Probability that something is malicious.

    #fasguard_option_value_type::double_val will contain a probablity in the
    range [0.0, 1.0].
*/
#define FASGUARD_OPTION_PROBABILITY_MALICIOUS UINT16_C(0x0002)

/**
    @brief Type of the layer 2 header.

    #fasguard_option_value_type::int_val will contain a DLT_ value, as
    specified at http://www.tcpdump.org/linktypes.html.
*/
#define FASGUARD_OPTION_LAYER2_TYPE UINT16_C(0x0003)

/**
    @brief Opaque handle for a single output stream.
*/
typedef void * fasguard_attack_output_type;

/**
    @brief Opaque handle for an attack group.
*/
typedef void * fasguard_attack_group_type;

/**
    @brief Opaque handle for an instance of an attack.
*/
typedef void * fasguard_attack_instance_type;

/**
    @brief Open a directory for writing STIX files, one file per attack group.

    Within the specified directory, the following directory structure will be
    created:
      - <tt>tmp/</tt>: Temporary files.
        - <tt><em>attack-group</em>/</tt>: Directory for a single attack group.
          - <tt>instances/</tt>: Per-instance files.
            - <tt><em>attack-instance</em></tt>: Partial STIX file for a
              single instance.
          - <tt>all.xml</tt>: STIX file for the attack group.
      - <tt>new/</tt>
        - <tt><em>attack-group</em>.xml</tt>: Newly available complete STIX file
          for a single attack group.
      - <tt>cur/</tt>
        - <tt><em>attack-group</em>.xml</tt>: Processed STIX file.

    Attacks in progress are stored in the <tt>tmp/</tt> directory. Packets are
    added to the appropriate
    <tt>tmp/<em>attack-group</em>/instances/<em>attack-instance</em></tt>
    file as they become available. When an instance is done
    (#fasguard_end_attack_instance), the <tt><em>attack-instance</em></tt> is
    appended to the appropriate
    <tt>tmp/<em>attack-group</em>/all.xml</tt> file. When the group is done
    (#fasguard_end_attack_group), the <tt>all.xml</tt> file gets closing tags
    appended, and the file is moved to <tt>new/<em>attack-group</em>.xml</tt>.

    A separate program may move files from <tt>new/</tt> to <tt>cur/</tt>, but
    that is outside the scope of this library.

    @return A valid output handle, or NULL if an error occured. If NULL is
            returned, errno will be set to indicate the error.
*/
fasguard_attack_output_type fasguard_open_attack_output(
    char const * directory,
    fasguard_option_type const * options);

/**
    @brief Flush an output stream.

    @return True on success, false on error. If false is returned, errno will
            be set to indicate the error.
*/
bool fasguard_flush_attack_output(
    fasguard_attack_output_type output);

/**
    @brief Flush and close an output stream.

    @note If there are any attack groups or instances that have been started but
          not ended, the behavior of this function is undefined.

    @note It is an error to use an output stream after this function is called
          on it.

    @return True on success, false on error. If false is returned, errno will
            be set to indicate the error.
*/
bool fasguard_close_attack_output(
    fasguard_attack_output_type output);

/**
    @brief Start a new group of related attacks.

    @return The new attack group's ID, or NULL on error. If NULL is returned,
            errno will be set to indicate the error.
*/
fasguard_attack_group_type fasguard_start_attack_group(
    fasguard_attack_output_type output,
    fasguard_option_type const * options);

/**
    @brief Mark the end of a group of related attacks.

    @note If there are any attack instances in this group that have been started
          but not ended, all future behavior for this output stream is
          undefined.

    @note It is an error to use an attack group after this function is called on
          it.

    @return True on success, false on error. If false is returned, errno will be
            set to indicate the error.
*/
bool fasguard_end_attack_group(
    fasguard_attack_group_type group);

/**
    @brief Start a new instance of an attack within the specified attack group.

    @return The new attack instance's ID, or NULL on error. If NULL is returned,
            errno will be set to indicate the error.
*/
fasguard_attack_instance_type fasguard_start_attack_instance(
    fasguard_attack_group_type group,
    fasguard_option_type const * options);

/**
    @brief Mark the end of a single attack.

    @note It is an error to use an attack instance after this function is called
          on it.

    @return True on success, false on error. If false is returned, errno will be
            set to indicate the error.
*/
bool fasguard_end_attack_instance(
    fasguard_attack_instance_type instance);

/**
    @brief Add a packet to an attack instance.

    Supported options:
      - #FASGUARD_OPTION_TIMESTAMP: Arrival time of the packet.
      - #FASGUARD_OPTION_PROBABILITY_MALICIOUS: Likelihood that the packet
        is part of an attack.
      - #FASGUARD_OPTION_LAYER2_TYPE: Type of layer 2 header. This option
        is mandatory if @p l3_offset is non-zero.

    @param[in] instance Attack instance to append this packet to.
    @param[in] packet_length Length of @p packet.
    @param[in] packet Packet data, which may include the layer 2
                      header.
    @param[in] l3_offset Offset of the layer 3 header within
                         @p packet. If no layer 2 header is present,
                         then this is zero.
    @param[in] options Options for the packet.
    @return True on success, false on error. If false is returned, errno will be
            set to indicate the error.
*/
bool fasguard_add_packet_to_attack_instance(
    fasguard_attack_instance_type instance,
    size_t packet_length,
    uint8_t const * packet,
    size_t l3_offset,
    fasguard_option_type const * options);


#ifdef __cplusplus
}
#endif

#endif
