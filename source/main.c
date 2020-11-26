/*
    Copyright (C) HWPORT.COM
    All rights reserved.
    Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
*/

#if !defined(_ISOC99_SOURCE)
# define _ISOC99_SOURCE (1L)
#endif

#if !defined(_GNU_SOURCE)
# define _GNU_SOURCE (1L)
#endif

#include <stddef.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <linux/netlink.h>
#include <linux/xfrm.h>

static char *hwport_strip_ansi_code(char *s_string);
static void hwport_output_puts(const char *s_string);

static const char *hwport_xfrm_name(unsigned int s_type);

static size_t hwport_dump_space(char *s_buffer, size_t s_buffer_size, int s_depth);
static size_t hwport_dump(char *s_buffer, size_t s_buffer_size, int s_depth, const void *s_data, size_t s_size);

static size_t hwport_dump_family(char *s_buffer, size_t s_buffer_size, int s_depth, unsigned int s_family);
static size_t hwport_dump_proto(char *s_buffer, size_t s_buffer_size, int s_depth, unsigned int s_proto);
static size_t hwport_dump_spi(char *s_buffer, size_t s_buffer_size, int s_depth, __u32 s_spi);

static size_t hwport_dump_xfrm_address(char *s_buffer, size_t s_buffer_size, int s_depth, unsigned int s_family, xfrm_address_t *s_address);
static size_t hwport_dump_xfrm_id(char *s_buffer, size_t s_buffer_size, int s_depth, unsigned int s_family, struct xfrm_id *s_id);
static size_t hwport_dump_xfrm_selector(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_selector *s_selector);
static size_t hwport_dump_xfrm_lifetime_cfg(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_lifetime_cfg *s_lifetime_cfg);
static size_t hwport_dump_xfrm_lifetime_cur(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_lifetime_cur *s_lifetime_cur);
static size_t hwport_dump_xfrm_stats(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_stats *s_stats);

static size_t hwport_dump_xfrm_usersa_info(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_usersa_info *s_usersa_info);
static size_t hwport_dump_xfrm_usersa_id(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_usersa_id *s_usersa_id);
static size_t hwport_dump_xfrm_userpolicy_info(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_userpolicy_info *s_userpolicy_info);
static size_t hwport_dump_xfrm_userpolicy_id(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_userpolicy_id *s_userpolicy_id);
static size_t hwport_dump_xfrm_userspi_info(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_userspi_info *s_userspi_info);
static size_t hwport_dump_xfrm_user_acquire(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_user_acquire *s_user_acquire);
static size_t hwport_dump_xfrm_user_expire(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_user_expire *s_user_expire);
static size_t hwport_dump_xfrm_user_polexpire(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_user_polexpire *s_user_polexpire);
static size_t hwport_dump_xfrm_usersa_flush(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_usersa_flush *s_usersa_flush);
static size_t hwport_dump_xfrm_aevent_id(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_aevent_id *s_aevent_id);
static size_t hwport_dump_xfrm_user_report(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_user_report *s_user_report);
#if defined(XFRM_MSG_NEWSADINFO) || defined(XFRM_MSG_GETSADINFO)
static size_t hwport_dump_xfrm_usersad_info(char *s_buffer, size_t s_buffer_size, int s_depth, __u32 *s_usersad_info);
#endif
#if defined(XFRM_MSG_NEWSPDINFO) || defined(XFRM_MSG_GETSPDINFO)
static size_t hwport_dump_xfrm_userspd_info(char *s_buffer, size_t s_buffer_size, int s_depth, __u32 *s_userspd_info);
#endif
#if defined(XFRM_MSG_MAPPING)
static size_t hwport_dump_xfrm_user_mapping(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_user_mapping *s_user_mapping);
#endif

int main(int s_argc, char **s_argv);

static char *hwport_strip_ansi_code(char *s_string)
{
    size_t s_string_size;

    size_t s_from_offset;
    size_t s_to_offset;

    int s_escape_sequence;

    int s_byte;

    if(s_string == ((char *)0)) {
        return((char *)0);
    }
    
    s_string_size = strlen(s_string);
  
    s_from_offset = (size_t)0u;
    s_to_offset = (size_t)0u;

    s_escape_sequence = 0;

    while(s_from_offset < s_string_size) {
        s_byte = (int)s_string[s_from_offset];
        if(s_byte == '\0') {
            break;
        }

        if(s_escape_sequence == 0) {
            if(s_byte == 0x1b) {
                s_escape_sequence = 1;
            }
            else {
                if(s_to_offset != s_from_offset) {
                    s_string[s_to_offset] = (char)s_byte;
                }
                ++s_to_offset;
            }
        }
        else if((isdigit(s_byte) == 0) && (s_byte != ';') && (s_byte != '[')) {
            s_escape_sequence = 0;
        }

        ++s_from_offset;
    }

    if(s_to_offset != s_from_offset) {
        s_string[s_to_offset] = '\0';
    }

    return(s_string);
}

static void hwport_output_puts(const char *s_string)
{
    static int sg_is_first = 0;
    static int sg_is_tty = 0;

    if(s_string == ((const char *)0)) {
        return;
    }

    if(sg_is_first == 0) {
        int s_fd;

        sg_is_first = 1;

        s_fd = fileno(stdout);
        if(s_fd != (-1)) {
            sg_is_tty = isatty(s_fd);
        }
    }

    if(sg_is_tty == 0) { /* pipe out, escape sequece need strip */
        char *s_dup_string;

        s_dup_string = hwport_strip_ansi_code(strdup(s_string));
        if(s_dup_string != ((char *)0)) {
            (void)fputs(s_dup_string, stdout);
            (void)fflush(stdout);
            
            free((void *)s_dup_string);

            return;
        }
    }

    /* normal tty out */
    (void)fputs(s_string, stdout);
    (void)fflush(stdout);
}

static const char *hwport_xfrm_name(unsigned int s_type)
{
    const char *s_result;

    switch(s_type) {
#if defined(NLMSG_NOOP)
        case NLMSG_NOOP:
            s_result = "NLMSG_NOOP";
            break;
#endif
#if defined(NLMSG_ERROR)
        case NLMSG_ERROR:
            s_result = "NLMSG_ERROR";
            break;
#endif
#if defined(NLMSG_DONE)
        case NLMSG_DONE:
            s_result = "NLMSG_DONE";
            break;
#endif
#if defined(NLMSG_OVERRUN)
        case NLMSG_OVERRUN:
            s_result = "NLMSG_OVERRUN";
            break;
#endif
#if defined(XFRM_MSG_NEWSA)
        case XFRM_MSG_NEWSA:
            s_result = "XFRM_MSG_NEWSA";
            break;
#endif
#if defined(XFRM_MSG_DELSA)
        case XFRM_MSG_DELSA:
            s_result = "XFRM_MSG_DELSA";
            break;
#endif
#if defined(XFRM_MSG_GETSA)
        case XFRM_MSG_GETSA:
            s_result = "XFRM_MSG_GETSA";
            break;
#endif
#if defined(XFRM_MSG_NEWPOLICY)
        case XFRM_MSG_NEWPOLICY:
            s_result = "XFRM_MSG_NEWPOLICY";
            break;
#endif
#if defined(XFRM_MSG_DELPOLICY)
        case XFRM_MSG_DELPOLICY:
            s_result = "XFRM_MSG_DELPOLICY";
            break;
#endif
#if defined(XFRM_MSG_GETPOLICY)
        case XFRM_MSG_GETPOLICY:
            s_result = "XFRM_MSG_GETPOLICY";
            break;
#endif
#if defined(XFRM_MSG_ALLOCSPI)
        case XFRM_MSG_ALLOCSPI:
            s_result = "XFRM_MSG_ALLOCSPI";
            break;
#endif
#if defined(XFRM_MSG_ACQUIRE)
        case XFRM_MSG_ACQUIRE:
            s_result = "XFRM_MSG_ACQUIRE";
            break;
#endif
#if defined(XFRM_MSG_EXPIRE)
        case XFRM_MSG_EXPIRE:
            s_result = "XFRM_MSG_EXPIRE";
            break;
#endif
#if defined(XFRM_MSG_UPDPOLICY)
        case XFRM_MSG_UPDPOLICY:
            s_result = "XFRM_MSG_UPDPOLICY";
            break;
#endif
#if defined(XFRM_MSG_UPDSA)
        case XFRM_MSG_UPDSA:
            s_result = "XFRM_MSG_UPDSA";
            break;
#endif
#if defined(XFRM_MSG_POLEXPIRE)
        case XFRM_MSG_POLEXPIRE:
            s_result = "XFRM_MSG_POLEXPIRE";
            break;
#endif
#if defined(XFRM_MSG_FLUSHSA)
        case XFRM_MSG_FLUSHSA:
            s_result = "XFRM_MSG_FLUSHSA";
            break;
#endif
#if defined(XFRM_MSG_FLUSHPOLICY)
        case XFRM_MSG_FLUSHPOLICY:
            s_result = "XFRM_MSG_FLUSHPOLICY";
            break;
#endif
#if defined(XFRM_MSG_NEWAE)
        case XFRM_MSG_NEWAE:
            s_result = "XFRM_MSG_NEWAE";
            break;
#endif
#if defined(XFRM_MSG_GETAE)
        case XFRM_MSG_GETAE:
            s_result = "XFRM_MSG_GETAE";
            break;
#endif
#if defined(XFRM_MSG_REPORT)
        case XFRM_MSG_REPORT:
            s_result = "XFRM_MSG_REPORT";
            break;
#endif
#if defined(XFRM_MSG_MIGRATE)
        case XFRM_MSG_MIGRATE:
            s_result = "XFRM_MSG_MIGRATE";
            break;
#endif
#if defined(XFRM_MSG_NEWSADINFO)
        case XFRM_MSG_NEWSADINFO:
            s_result = "XFRM_MSG_NEWSADINFO";
            break;
#endif
#if defined(XFRM_MSG_GETSADINFO)
        case XFRM_MSG_GETSADINFO:
            s_result = "XFRM_MSG_GETSADINFO";
            break;
#endif
#if defined(XFRM_MSG_NEWSPDINFO)
        case XFRM_MSG_NEWSPDINFO:
            s_result = "XFRM_MSG_NEWSPDINFO";
            break;
#endif
#if defined(XFRM_MSG_GETSPDINFO)
        case XFRM_MSG_GETSPDINFO:
            s_result = "XFRM_MSG_GETSPDINFO";
            break;
#endif
#if defined(MAPPING)
        case XFRM_MSG_MAPPING:
            s_result = "XFRM_MSG_MAPPING";
            break;
#endif
        default:
            s_result = "XFRM_MSG_??? (UNKNOWN)";
            break;
    }

    return(s_result);
}

static size_t hwport_dump_space(char *s_buffer, size_t s_buffer_size, int s_depth)
{
    size_t s_offset;
    int s_count;

    s_offset = (size_t)0u;
    for(s_count = 0;s_count < s_depth;s_count++) {
        s_offset += (size_t)snprintf(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            "  "
        );
    }

    return(s_offset);
}

static size_t hwport_dump(char *s_buffer, size_t s_buffer_size, int s_depth, const void *s_data, size_t s_size)
{
    size_t s_offset;

    size_t s_o;
    size_t s_w;
    size_t s_i;
    uint8_t s_b[17];

    s_offset = (size_t)0u;

    s_b[16] = (uint8_t)'\0';
    s_o = (size_t)0u;

    while(s_o < s_size) {
        s_w = ((s_size - s_o) < ((size_t)16u)) ? (s_size - s_o) : ((size_t)16u);

        s_offset += hwport_dump_space(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            s_depth
        );

        s_offset += (size_t)snprintf(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            "%08lX",
            (unsigned long)s_o
        );

        for(s_i = (size_t)0u;s_i < s_w;s_i++){
            if(s_i == ((size_t)8u)) {
                s_offset += (size_t)snprintf(
                    (char *)(&s_buffer[s_offset]),
                    s_buffer_size - s_offset,
                    " | "
                );
            }
            else {
                s_offset += (size_t)snprintf(
                    (char *)(&s_buffer[s_offset]),
                    s_buffer_size - s_offset,
                    " "
                );
            }

            s_b[s_i] = *(((const uint8_t *)s_data) + s_o + s_i);

            s_offset += (size_t)snprintf(
                (char *)(&s_buffer[s_offset]),
                s_buffer_size - s_offset,
                "%02X",
                (unsigned int)s_b[s_i]
            );

            if((s_b[s_i] & 0x80) || (s_b[s_i] < ' ')) {
                s_b[s_i] = '.';
            }
        }

        while(s_i < 16) {
            if(s_i == 8) {
                s_offset += (size_t)snprintf(
                    (char *)(&s_buffer[s_offset]),
                    s_buffer_size - s_offset,
                    "     "
                );
            }
            else {
                s_offset += (size_t)snprintf(
                    (char *)(&s_buffer[s_offset]),
                    s_buffer_size - s_offset,
                    "   "
                );
            }

            s_b[s_i] = ' ';
            ++s_i;
        }

        s_offset += (size_t)snprintf(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            " [%s]\n",
            (char *)(&s_b[0])
        );

        s_o += (size_t)16u;
    }

    return(s_offset);
}

static size_t hwport_dump_family(char *s_buffer, size_t s_buffer_size, int s_depth, unsigned int s_family)
{
    size_t s_offset;

    const char *c_family_name;

    s_offset = (size_t)0u;

    if(s_family == AF_UNSPEC) {
        c_family_name = "UNSPEC";
    }
    else if(s_family == AF_INET) {
        c_family_name = "INET";
    }
    else if(s_family == AF_INET6) {
        c_family_name = "INET6";
    }
    else {
        c_family_name = "?";
    }

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "family: %u[%04XH] - %s\n",
        s_family,
        s_family,
        c_family_name
    );

    return(s_offset);
}

struct hwport_proto_table_ts {
    const char *m_name;
    unsigned int m_value;
};
static size_t hwport_dump_proto(char *s_buffer, size_t s_buffer_size, int s_depth, unsigned int s_proto)
{
    static struct hwport_proto_table_ts s_pre_compare_table[] = {
        {"ip", IPPROTO_IP},
        {"icmp", IPPROTO_ICMP},
        {"igmp", IPPROTO_IGMP},
        {"tcp", IPPROTO_TCP},
        {"udp", IPPROTO_UDP},
        {"ipv6", IPPROTO_IPV6},
        {"routing", IPPROTO_ROUTING},
        {"gre", IPPROTO_GRE},
        {"esp", IPPROTO_ESP},
        {"ah", IPPROTO_AH},
        {"ipv6-icmp", IPPROTO_ICMPV6},
        {"raw", IPPROTO_RAW},
        {(const char *)0, 0u}
    };
    int s_pre_compare_index = 0;

    size_t s_offset;

    struct protoent *s_protoent;
    const char *c_proto_name;

    s_offset = (size_t)0u;

    setprotoent(0);

    c_proto_name = (const char *)0;
    s_protoent = getprotobynumber((int)s_proto);
    if(s_protoent != ((struct protoent *)0)) {
        c_proto_name = s_protoent->p_name;
    }
    if(c_proto_name == ((const char *)0)) {
        while(s_pre_compare_table[s_pre_compare_index].m_name != ((const char *)0)) {
            if(s_pre_compare_table[s_pre_compare_index].m_value == s_proto) {
                c_proto_name = s_pre_compare_table[s_pre_compare_index].m_name;
            }
 
            ++s_pre_compare_index;
        }

        if(c_proto_name == ((const char *)0)) {
            c_proto_name = "?";
        }
    }

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "proto: %u[%02XH] - %s\n",
        s_proto,
        s_proto,
        c_proto_name
    );

    endprotoent();

    return(s_offset);
}

static size_t hwport_dump_spi(char *s_buffer, size_t s_buffer_size, int s_depth, __u32 s_spi)
{
    size_t s_offset;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "spi: %lu[%08lXH]\n",
        (unsigned long)s_spi,
        (unsigned long)s_spi
    );

    return(s_offset);
}

static size_t hwport_dump_xfrm_address(char *s_buffer, size_t s_buffer_size, int s_depth, unsigned int s_family, xfrm_address_t *s_address)
{
    size_t s_offset;
    char s_in_addr_string[ 64 ];
    char s_in6_addr_string[ 64 ];
    struct in_addr s_in_addr; 
    struct in6_addr s_in6_addr; 

    s_offset = (size_t)0u;

    s_in_addr.s_addr = s_address->a4;
    (void)memcpy((void *)(&s_in6_addr), (const void *)(&s_address->a6[0]), sizeof(s_address->a6));

    if(s_family == AF_INET) {
        s_offset += hwport_dump_space(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            s_depth
        );
        s_offset += (size_t)snprintf(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            "IPv4: %s\n",
            inet_ntop(AF_INET, &s_in_addr, (void *)(&s_in_addr_string[0]), (socklen_t)sizeof(s_in_addr_string))
        );
    }
    else if(s_family == AF_INET6) {
        s_offset += hwport_dump_space(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            s_depth
        );
        s_offset += (size_t)snprintf(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            "IPv6: %s\n",
            inet_ntop(AF_INET6, &s_in6_addr, (void *)(&s_in6_addr_string[0]), (socklen_t)sizeof(s_in6_addr_string))
        );
    }
    else if(IN6_IS_ADDR_V4MAPPED(&s_in6_addr)) {
        s_offset += hwport_dump_space(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            s_depth
        );
        s_offset += (size_t)snprintf(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            "IPv4 (MAPPED): %s (%s)\n",
            inet_ntop(AF_INET, &s_in_addr, (void *)(&s_in_addr_string[0]), (socklen_t)sizeof(s_in_addr_string)),
            inet_ntop(AF_INET6, &s_in6_addr, (void *)(&s_in6_addr_string[0]), (socklen_t)sizeof(s_in6_addr_string))
        );
    }
    else if(IN6_IS_ADDR_V4COMPAT(&s_in6_addr)) {
        s_offset += hwport_dump_space(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            s_depth
        );
        s_offset += (size_t)snprintf(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            "IPv4 (COMPAT): %s (%s)\n",
            inet_ntop(AF_INET, &s_in_addr, (void *)(&s_in_addr_string[0]), (socklen_t)sizeof(s_in_addr_string)),
            inet_ntop(AF_INET6, &s_in6_addr, (void *)(&s_in6_addr_string[0]), (socklen_t)sizeof(s_in6_addr_string))
        );
    }
    else if(IN6_IS_ADDR_UNSPECIFIED(&s_in6_addr)) {
        s_offset += hwport_dump_space(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            s_depth
        );
        s_offset += (size_t)snprintf(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            "IPv4 (UNSPECIFIED): %s (%s)\n",
            inet_ntop(AF_INET, &s_in_addr, (void *)(&s_in_addr_string[0]), (socklen_t)sizeof(s_in_addr_string)),
            inet_ntop(AF_INET6, &s_in6_addr, (void *)(&s_in6_addr_string[0]), (socklen_t)sizeof(s_in6_addr_string))
        );
    }
    else if((s_address->a6[1] == ((__be32)htonl(0))) && (s_address->a6[2] == ((__be32)htonl(0))) && (s_address->a6[3] == ((__be32)htonl(0)))) {
        s_offset += hwport_dump_space(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            s_depth
        );
        s_offset += (size_t)snprintf(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            "IPv4 (v4 or v6 ?): %s (%s)\n",
            inet_ntop(AF_INET, &s_in_addr, (void *)(&s_in_addr_string[0]), (socklen_t)sizeof(s_in_addr_string)),
            inet_ntop(AF_INET6, &s_in6_addr, (void *)(&s_in6_addr_string[0]), (socklen_t)sizeof(s_in6_addr_string))
        );
    } 
    else {
        s_offset += hwport_dump_space(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            s_depth
        );
        s_offset += (size_t)snprintf(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            "%s: family=%u[%04XH]\n",
            (s_family == AF_UNSPEC) ? "IPv? (UNSPEC)" : "IPv?",
            s_family,
            s_family
        );

        s_offset += hwport_dump_xfrm_address(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            s_depth + 1,
            AF_INET,
            s_address
        );
        s_offset += hwport_dump_xfrm_address(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            s_depth + 1,
            AF_INET6,
            s_address
        );

        s_offset += hwport_dump_space(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            s_depth + 1
        );
        s_offset += (size_t)snprintf(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            "hex dump:\n"
        );
        s_offset += hwport_dump(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            s_depth + 2,
            (const void *)s_address,
            sizeof(*s_address)
        );
    }

    return(s_offset);
}

static size_t hwport_dump_xfrm_id(char *s_buffer, size_t s_buffer_size, int s_depth, unsigned int s_family, struct xfrm_id *s_id)
{
    size_t s_offset;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "daddr:\n"
    );
    s_offset += hwport_dump_xfrm_address(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        s_family,
        (xfrm_address_t *)(&s_id->daddr)
    );

    s_offset += hwport_dump_spi(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth,
        (__u32)ntohl(s_id->spi)
    );

    s_offset += hwport_dump_proto(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth,
        (unsigned int)s_id->proto
    );

    return(s_offset);
}

static size_t hwport_dump_xfrm_selector(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_selector *s_selector)
{
    size_t s_offset;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "daddr:\n"
    );
    s_offset += hwport_dump_xfrm_address(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        s_selector->family,
        (xfrm_address_t *)(&s_selector->daddr)
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "saddr:\n"
    );
    s_offset += hwport_dump_xfrm_address(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        s_selector->family,
        (xfrm_address_t *)(&s_selector->saddr)
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "dport/mask: %u[%04XH]/%u[%04XH]\n",
        (unsigned int)ntohs(s_selector->dport),
        (unsigned int)ntohs(s_selector->dport),
        (unsigned int)ntohs(s_selector->dport_mask),
        (unsigned int)ntohs(s_selector->dport_mask)
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "sport/mask: %u[%04XH]/%u[%04XH]\n",
        (unsigned int)ntohs(s_selector->sport),
        (unsigned int)ntohs(s_selector->sport),
        (unsigned int)ntohs(s_selector->sport_mask),
        (unsigned int)ntohs(s_selector->sport_mask)
    );

    s_offset += hwport_dump_family(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth,
        (unsigned int)s_selector->family
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "prefixlen_d: %u\n",
        (unsigned int)s_selector->prefixlen_d
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "prefixlen_s: %u\n",
        (unsigned int)s_selector->prefixlen_s
    );

    s_offset += hwport_dump_proto(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth,
        (unsigned int)s_selector->proto
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "ifindex: %d\n",
        (int)s_selector->ifindex
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "user: %u[%02XH]\n",
        (unsigned int)s_selector->user,
        (unsigned int)s_selector->user
    );

    return(s_offset);
}

static size_t hwport_dump_xfrm_lifetime_cfg(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_lifetime_cfg *s_lifetime_cfg)
{
    size_t s_offset;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "soft_byte_limit/hard_byte_limit: %llu/%llu\n",
        (unsigned long long)s_lifetime_cfg->soft_byte_limit,
        (unsigned long long)s_lifetime_cfg->hard_byte_limit
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "soft_packet_limit/hard_packet_limit: %llu/%llu\n",
        (unsigned long long)s_lifetime_cfg->soft_packet_limit,
        (unsigned long long)s_lifetime_cfg->hard_packet_limit
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "soft_add_expires_seconds/hard_add_expires_seconds: %llu/%llu\n",
        (unsigned long long)s_lifetime_cfg->soft_add_expires_seconds,
        (unsigned long long)s_lifetime_cfg->hard_add_expires_seconds
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "soft_use_expires_seconds/hard_use_expires_seconds: %llu/%llu\n",
        (unsigned long long)s_lifetime_cfg->soft_use_expires_seconds,
        (unsigned long long)s_lifetime_cfg->hard_use_expires_seconds
    );

    return(s_offset);
}

static size_t hwport_dump_xfrm_lifetime_cur(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_lifetime_cur *s_lifetime_cur)
{
    size_t s_offset;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "bytes: %llu\n",
        (unsigned long long)s_lifetime_cur->bytes
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "packets: %llu\n",
        (unsigned long long)s_lifetime_cur->packets
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "add_time: %llu\n",
        (unsigned long long)s_lifetime_cur->add_time
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "use_time: %llu\n",
        (unsigned long long)s_lifetime_cur->use_time
    );

    return(s_offset);
}

static size_t hwport_dump_xfrm_stats(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_stats *s_stats)
{
    size_t s_offset;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "replay_window/replay: %lu/%lu\n",
        (unsigned long)s_stats->replay_window,
        (unsigned long)s_stats->replay
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "integrity_failed: %lu[%08lXH]\n",
        (unsigned long)s_stats->integrity_failed,
        (unsigned long)s_stats->integrity_failed
    );

    return(s_offset);
}

static size_t hwport_dump_xfrm_usersa_info(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_usersa_info *s_usersa_info)
{
    size_t s_offset;
    const char *c_mode_name;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "selector:\n"
    );
    s_offset += hwport_dump_xfrm_selector(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        (struct xfrm_selector *)(&s_usersa_info->sel) 
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "id:\n"
    );
    s_offset += hwport_dump_xfrm_id(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        s_usersa_info->family,
        (struct xfrm_id *)(&s_usersa_info->id) 
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "saddr:\n"
    );
    s_offset += hwport_dump_xfrm_address(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        s_usersa_info->family,
        (xfrm_address_t *)(&s_usersa_info->saddr) 
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "lifetime_cfg:\n"
    );
    s_offset += hwport_dump_xfrm_lifetime_cfg(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        (struct xfrm_lifetime_cfg *)(&s_usersa_info->lft) 
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "lifetime_cur:\n"
    );
    s_offset += hwport_dump_xfrm_lifetime_cur(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        (struct xfrm_lifetime_cur *)(&s_usersa_info->curlft) 
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "stats:\n"
    );
    s_offset += hwport_dump_xfrm_stats(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        (struct xfrm_stats *)(&s_usersa_info->stats) 
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "seq: %lu\n",
        (unsigned long)s_usersa_info->seq
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "reqid: %lu\n",
        (unsigned long)s_usersa_info->reqid
    );

    s_offset += hwport_dump_family(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth,
        (unsigned int)s_usersa_info->family
    );
   
    if(s_usersa_info->mode == XFRM_MODE_TRANSPORT) {
        c_mode_name = "TRANSPORT";
    }
    else if(s_usersa_info->mode == XFRM_MODE_TUNNEL) {
        c_mode_name = "TUNNEL";
    }
    else if(s_usersa_info->mode == XFRM_MODE_ROUTEOPTIMIZATION) {
        c_mode_name = "ROUTEOPTIMIZATION";
    }
    else if(s_usersa_info->mode == XFRM_MODE_IN_TRIGGER) {
        c_mode_name = "IN_TRIGGER";
    }
    else if(s_usersa_info->mode == XFRM_MODE_BEET) {
        c_mode_name = "BEET";
    }
    else {
        c_mode_name = "?";
    }
    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "mode: %u[%02XH] - %s\n",
        (unsigned int)s_usersa_info->mode,
        (unsigned int)s_usersa_info->mode,
        c_mode_name
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "replay_window: %u[%02XH]\n",
        (unsigned int)s_usersa_info->replay_window,
        (unsigned int)s_usersa_info->replay_window
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "flags: %u[%02XH] - %s%s%s%s%s%s%s%s%s%s\n",
        (unsigned int)s_usersa_info->flags,
        (unsigned int)s_usersa_info->flags,
        (s_usersa_info->flags) ? "" : "<NONE FLAGS>",
#if defined(XFRM_STATE_NOECN)
        (s_usersa_info->flags & XFRM_STATE_NOECN) ? "{NOECN}" : "",
#else
        "",
#endif
#if defined(XFRM_STATE_DECAP_DSCP)
        (s_usersa_info->flags & XFRM_STATE_DECAP_DSCP) ? "{DECAP_DSCP}" : "",
#else
        "",
#endif
#if defined(XFRM_STATE_NOPMTUDISC)
        (s_usersa_info->flags & XFRM_STATE_NOPMTUDISC) ? "{NOPMTUDISC}" : "",
#else
        "",
#endif
#if defined(XFRM_STATE_WILDRECV)
        (s_usersa_info->flags & XFRM_STATE_WILDRECV) ? "{WILDRECV}" : "",
#else
        "",
#endif
#if defined(XFRM_STATE_ICMP)
        (s_usersa_info->flags & XFRM_STATE_ICMP) ? "{ICMP}" : "",
#else
        "",
#endif
#if defined(XFRM_STATE_AF_UNSPEC)
        (s_usersa_info->flags & XFRM_STATE_AF_UNSPEC) ? "{AF_UNSPEC}" : "",
#else
        "",
#endif
#if defined(XFRM_STATE_ALIGN4)
        (s_usersa_info->flags & XFRM_STATE_ALIGN4) ? "{ALIGN4}" : "",
#else
        "",
#endif
#if defined(XFRM_STATE_ESN)
        (s_usersa_info->flags & XFRM_STATE_ESN) ? "{ESN}" : "",
#else
        "",
#endif
        "" /* for trailer discard comma */
    );

    return(s_offset);
}

static size_t hwport_dump_xfrm_usersa_id(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_usersa_id *s_usersa_id)
{
    size_t s_offset;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "daddr:\n"
    );
    s_offset += hwport_dump_xfrm_address(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        s_usersa_id->family,
        (xfrm_address_t *)(&s_usersa_id->daddr) 
    );

    s_offset += hwport_dump_spi(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth,
        (__u32)ntohl(s_usersa_id->spi)
    );

    s_offset += hwport_dump_family(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth,
        (unsigned int)s_usersa_id->family
    );

    s_offset += hwport_dump_proto(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth,
        (unsigned int)s_usersa_id->proto
    );

    return(s_offset);
}

static size_t hwport_dump_xfrm_userpolicy_info(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_userpolicy_info *s_userpolicy_info)
{
    size_t s_offset;

    const char *c_action_name;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "selector:\n"
    );
    s_offset += hwport_dump_xfrm_selector(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        (struct xfrm_selector *)(&s_userpolicy_info->sel) 
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "lifetime_cfg:\n"
    );
    s_offset += hwport_dump_xfrm_lifetime_cfg(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        (struct xfrm_lifetime_cfg *)(&s_userpolicy_info->lft) 
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "lifetime_cur:\n"
    );
    s_offset += hwport_dump_xfrm_lifetime_cur(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        (struct xfrm_lifetime_cur *)(&s_userpolicy_info->curlft) 
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "priority: %lu\n",
        (unsigned long)s_userpolicy_info->priority
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "index: %lu\n",
        (unsigned long)s_userpolicy_info->index
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "dir: %u\n",
        (unsigned int)s_userpolicy_info->dir
    );

    if(s_userpolicy_info->action == XFRM_POLICY_ALLOW) {
        c_action_name = "POLICY_ALLOW";
    }
    else if(s_userpolicy_info->action == XFRM_POLICY_BLOCK) {
        c_action_name = "POLICY_BLOCK";
    }
    else {
        c_action_name = "?";
    }
    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "action: %u - %s\n",
        (unsigned int)s_userpolicy_info->action,
        c_action_name
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "flags: %u[%02XH] - %s%s%s%s\n",
        (unsigned int)s_userpolicy_info->flags,
        (unsigned int)s_userpolicy_info->flags,
        (s_userpolicy_info->flags) ? "" : "<NONE FLAGS>",
#if defined(XFRM_POLICY_LOCALOK)
        (s_userpolicy_info->flags & XFRM_POLICY_LOCALOK) ? "{POLICY_LOCALOK}" : "",
#else
        "",
#endif
#if defined(XFRM_POLICY_ICMP)
        (s_userpolicy_info->flags & XFRM_POLICY_ICMP) ? "{POLICY_ICMP}" : "",
#else
        "",
#endif
        "" /* for trailer discard comma */
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "share: %u[%02XH]\n",
        (unsigned int)s_userpolicy_info->share,
        (unsigned int)s_userpolicy_info->share
    );

    return(s_offset);
}

static size_t hwport_dump_xfrm_userpolicy_id(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_userpolicy_id *s_userpolicy_id)
{
    size_t s_offset;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "selector:\n"
    );
    s_offset += hwport_dump_xfrm_selector(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        (struct xfrm_selector *)(&s_userpolicy_id->sel) 
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "index: %lu\n",
        (unsigned long)s_userpolicy_id->index
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "dir: %u\n",
        (unsigned int)s_userpolicy_id->dir
    );

    return(s_offset);
}

static size_t hwport_dump_xfrm_userspi_info(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_userspi_info *s_userspi_info)
{
    size_t s_offset;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "info:\n"
    );
    s_offset += hwport_dump_xfrm_usersa_info(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        (struct xfrm_usersa_info *)(&s_userspi_info->info) 
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "min/max: %lu/%lu\n",
        (unsigned long)s_userspi_info->min,
        (unsigned long)s_userspi_info->max
    );

    return(s_offset);
}

static size_t hwport_dump_xfrm_user_acquire(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_user_acquire *s_user_acquire)
{
    size_t s_offset;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "id:\n"
    );
    s_offset += hwport_dump_xfrm_id(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        s_user_acquire->sel.family,
        (struct xfrm_id *)(&s_user_acquire->id) 
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "saddr:\n"
    );
    s_offset += hwport_dump_xfrm_address(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        s_user_acquire->sel.family,
        (xfrm_address_t *)(&s_user_acquire->saddr)
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "selector:\n"
    );
    s_offset += hwport_dump_xfrm_selector(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        (struct xfrm_selector *)(&s_user_acquire->sel) 
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "policy:\n"
    );
    s_offset += hwport_dump_xfrm_userpolicy_info(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        (struct xfrm_userpolicy_info *)(&s_user_acquire->policy) 
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "aalgos/ealgos/calgos: %lu[%08lXH]/%lu[%08lXH]/%lu[%08lXH]\n",
        (unsigned long)s_user_acquire->aalgos,
        (unsigned long)s_user_acquire->aalgos,
        (unsigned long)s_user_acquire->ealgos,
        (unsigned long)s_user_acquire->ealgos,
        (unsigned long)s_user_acquire->calgos,
        (unsigned long)s_user_acquire->calgos
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "seq: %lu\n",
        (unsigned long)s_user_acquire->seq
    );

    return(s_offset);
}

static size_t hwport_dump_xfrm_user_expire(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_user_expire *s_user_expire)
{
    size_t s_offset;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "state:\n"
    );
    s_offset += hwport_dump_xfrm_usersa_info(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        (struct xfrm_usersa_info *)(&s_user_expire->state) 
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "hard: %u[%02XH]\n",
        (unsigned int)s_user_expire->hard,
        (unsigned int)s_user_expire->hard
    );

    return(s_offset);
}

static size_t hwport_dump_xfrm_user_polexpire(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_user_polexpire *s_user_polexpire)
{
    size_t s_offset;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "pol:\n"
    );
    s_offset += hwport_dump_xfrm_userpolicy_info(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        (struct xfrm_userpolicy_info *)(&s_user_polexpire->pol) 
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "hard: %u[%02XH]\n",
        (unsigned int)s_user_polexpire->hard,
        (unsigned int)s_user_polexpire->hard
    );

    return(s_offset);
}

static size_t hwport_dump_xfrm_usersa_flush(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_usersa_flush *s_usersa_flush)
{
    size_t s_offset;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_proto(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth,
        (unsigned int)s_usersa_flush->proto
    );

    return(s_offset);
}

static size_t hwport_dump_xfrm_aevent_id(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_aevent_id *s_aevent_id)
{
    size_t s_offset;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "sa_id:\n"
    );
    s_offset += hwport_dump_xfrm_usersa_id(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        (struct xfrm_usersa_id *)(&s_aevent_id->sa_id)
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "saddr:\n"
    );
    s_offset += hwport_dump_xfrm_address(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        AF_UNSPEC,
        (xfrm_address_t *)(&s_aevent_id->saddr)
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "flags: %lu[%08lXH]\n",
        (unsigned long)s_aevent_id->flags,
        (unsigned long)s_aevent_id->flags
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "reqid: %lu[%08lXH]\n",
        (unsigned long)s_aevent_id->reqid,
        (unsigned long)s_aevent_id->reqid
    );

    return(s_offset);
}

static size_t hwport_dump_xfrm_user_report(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_user_report *s_user_report)
{
    size_t s_offset;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_proto(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth,
        (unsigned int)s_user_report->proto
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "selector:\n"
    );
    s_offset += hwport_dump_xfrm_selector(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        (struct xfrm_selector *)(&s_user_report->sel) 
    );

    return(s_offset);
}

#if defined(XFRM_MSG_NEWSADINFO) || defined(XFRM_MSG_GETSADINFO)
static size_t hwport_dump_xfrm_usersad_info(char *s_buffer, size_t s_buffer_size, int s_depth, __u32 *s_usersad_info)
{
    size_t s_offset;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "sad: %lu[%08lXH]\n",
        (unsigned long)(*s_usersad_info),
        (unsigned long)(*s_usersad_info)
    );

    return(s_offset);
}
#endif

#if defined(XFRM_MSG_NEWSPDINFO) || defined(XFRM_MSG_GETSPDINFO)
static size_t hwport_dump_xfrm_userspd_info(char *s_buffer, size_t s_buffer_size, int s_depth, __u32 *s_userspd_info)
{
    size_t s_offset;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "spd: %lu[%08lXH]\n",
        (unsigned long)(*s_userspd_info),
        (unsigned long)(*s_userspd_info)
    );

    return(s_offset);
}
#endif

#if defined(XFRM_MSG_MAPPING)
static size_t hwport_dump_xfrm_user_mapping(char *s_buffer, size_t s_buffer_size, int s_depth, struct xfrm_user_mapping *s_user_mapping)
{
    size_t s_offset;

    s_offset = (size_t)0u;

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "id:\n"
    );
    s_offset += hwport_dump_xfrm_usersa_id(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        (struct xfrm_usersa_id *)(&s_user_mapping->id) 
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "reqid: %lu[%08lXH]\n",
        (unsigned long)s_user_mapping->reqid,
        (unsigned long)s_user_mapping->reqid
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "old_saddr:\n"
    );
    s_offset += hwport_dump_xfrm_address(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        AF_UNSPEC,
        (xfrm_address_t *)(&s_user_mapping->old_saddr)
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "old_sport: %u\n",
        (unsigned int)s_user_mapping->old_sport
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "new_saddr:\n"
    );
    s_offset += hwport_dump_xfrm_address(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth + 1,
        AF_UNSPEC,
        (xfrm_address_t *)(&s_user_mapping->new_saddr)
    );

    s_offset += hwport_dump_space(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        s_depth
    );
    s_offset += (size_t)snprintf(
        (char *)(&s_buffer[s_offset]),
        s_buffer_size - s_offset,
        "net_sport: %u\n",
        (unsigned int)s_user_mapping->new_sport
    );

    return(s_offset);
}
#endif

#if 0L
#define typecheck(type,x) \
({      type __dummy; \
        typeof(x) __dummy2; \
        (void)(&__dummy == &__dummy2); \
        1; \
})
#define time_after_eq(a,b)      \
        (typecheck(unsigned long, a) && \
         typecheck(unsigned long, b) && \
         ((long)(a) - (long)(b) >= 0))
#define ULONG_MAX (~0UL)
#define get_delta_jiffies(a, b) (time_after_eq(a, b)) ? a - b : (ULONG_MAX - b) + a;

static int test(void);
static int test(void)
{
    u_long s_x;
    u_long s_y;
    u_long delta;

    s_y = 0xfffffffful;
    s_x = s_y + 10ul;

    delta = get_delta_jiffies(s_x, s_y);
    printf("[%lu]\n", delta);
 
    return(0);
}
#endif

int main(int s_argc, char **s_argv)
{
    __u32 s_nl_groups;
    int s_socket;
    struct sockaddr_nl s_sockaddr_nl; 
    socklen_t s_socklen;

    size_t s_buffer_size;
    void *s_buffer;
    size_t s_output_buffer_size;
    char *s_output_buffer;
    size_t s_output_offset;
    int s_depth;

    ssize_t s_recv_bytes;

    int s_is_break;

    size_t s_msg_size;
    struct nlmsghdr *s_nlmsghdr;
    size_t s_payload_size;
    void *s_payload;
    size_t s_message_size;
        
    (void)s_argc;
    (void)s_argv;

    (void)fprintf(stdout, "NETLINK IPSEC MONITOR\n\n");

#if 0L
    test();
#endif

    /*
        XFRMNLGRP_NONE,
        XFRMNLGRP_ACQUIRE,
        XFRMNLGRP_EXPIRE,
        XFRMNLGRP_SA,
        XFRMNLGRP_POLICY,
        XFRMNLGRP_AEVENTS,
        XFRMNLGRP_REPORT,
        XFRMNLGRP_MIGRATE,
        XFRMNLGRP_MAPPING,
        __XFRMNLGRP_MAX
    */
    s_nl_groups = XFRMNLGRP_NONE;
#if defined(XFRMNLGRP_ACQUIRE)
    s_nl_groups |= XFRMNLGRP_ACQUIRE;
#endif
#if defined(XFRMNLGRP_EXPIRE)
    s_nl_groups |= XFRMNLGRP_EXPIRE;
#endif
#if defined(XFRMNLGRP_SA)
    s_nl_groups |= XFRMNLGRP_SA;
#endif
#if defined(XFRMNLGRP_POLICY)
    s_nl_groups |= XFRMNLGRP_POLICY;
#endif
#if defined(XFRMNLGRP_AEVENTS)
    s_nl_groups |= XFRMNLGRP_AEVENTS;
#endif
#if defined(XFRMNLGRP_REPORT)
    s_nl_groups |= XFRMNLGRP_REPORT;
#endif
#if defined(XFRMNLGRP_MIGRATE)
    s_nl_groups |= XFRMNLGRP_MIGRATE;
#endif
#if defined(XFRMNLGRP_MAPPING)
    s_nl_groups |= XFRMNLGRP_MAPPING;
#endif

    s_socket = socket(PF_NETLINK, SOCK_RAW, NETLINK_XFRM /* 6 - ipsec */);
    if(s_socket == (-1)) {
        perror("socket");
        return(EXIT_FAILURE);
    }

    (void)memset((void *)(&s_sockaddr_nl), 0, sizeof(s_sockaddr_nl));
    s_sockaddr_nl.nl_family = AF_NETLINK;
    s_sockaddr_nl.nl_pad = (unsigned short)0u;
    s_sockaddr_nl.nl_pid = (pid_t)0;
    s_sockaddr_nl.nl_groups = s_nl_groups; /* Multicast groups mask */

    if(bind(s_socket, (const struct sockaddr *)(&s_sockaddr_nl), (socklen_t)sizeof(s_sockaddr_nl)) == (-1)) {
        perror("bind");
        return(EXIT_FAILURE);
    }
    (void)fprintf(stdout, "listening...\n");   
 
    s_buffer_size = (size_t)(512 << 10);
    s_buffer = malloc(s_buffer_size);
    if(s_buffer == ((void *)0)) {
        (void)fprintf(stderr, "not enough memory !\n");
        close(s_socket);
        return(EXIT_FAILURE);
    }

    for(;;) {
        (void)memset((void *)(&s_sockaddr_nl), 0, sizeof(s_sockaddr_nl));
        s_socklen = (socklen_t)sizeof(s_sockaddr_nl);
        s_recv_bytes = recvfrom(
            s_socket,
            s_buffer,
            s_buffer_size,
            MSG_NOSIGNAL,
            (struct sockaddr *)(&s_sockaddr_nl),
            (socklen_t *)(&s_socklen)
        );
        if(s_recv_bytes == ((ssize_t)(-1))) {
            perror("recvfrom");
            break;
        }
#if 0L /* DEBUG */
        (void)fprintf(
            stdout,
            "recvfrom %ld bytes (pid=%lu, groups=%08lXH)\n",
            (long)s_recv_bytes,
            (long)s_sockaddr_nl.nl_pid,
            (unsigned long)s_sockaddr_nl.nl_groups
        );
#endif

        if(s_sockaddr_nl.nl_family != AF_NETLINK) {
            (void)fprintf(stderr, "nl_family != AF_NETLINK is ignore (nl_family=%ld)\n", (long)s_sockaddr_nl.nl_family);
            continue;
        }

        if(s_sockaddr_nl.nl_pid != ((pid_t)0)) {
            /* sender pid 0 is ignore */
            (void)fprintf(stderr, "sender pid 0 is ignore (pid=%ld)\n", (long)s_sockaddr_nl.nl_pid);
            continue;
        }

        s_output_buffer_size = s_buffer_size - ((size_t)s_recv_bytes);
        s_output_buffer = ((char *)s_buffer) + s_recv_bytes;
        s_output_offset = (size_t)0;

        s_is_break = 0;

        s_msg_size = (size_t)s_recv_bytes;
        for(s_nlmsghdr = (struct nlmsghdr *)s_buffer;(s_is_break == 0) && NLMSG_OK(s_nlmsghdr, s_msg_size);s_nlmsghdr = NLMSG_NEXT(s_nlmsghdr, s_msg_size)) {
            s_payload_size = (size_t)NLMSG_PAYLOAD(s_nlmsghdr, 0);
            s_payload = NLMSG_DATA(s_nlmsghdr);

            s_depth = 0;
            s_output_offset += hwport_dump_space(
                (char *)(&s_output_buffer[s_output_offset]),
                s_output_buffer_size - s_output_offset,
                s_depth
            );

            s_output_offset += (size_t)snprintf(
                (char *)(&s_output_buffer[s_output_offset]),
                s_output_buffer_size - s_output_offset,
                "* \"\x1b[1;33m%s\x1b[0m\" (type=%lu[%04lXH], flags=%04lXH[%s%s%s%s%s%s%s%s%s%s%s%s%s%s], seq=%lu, pid=%lu, len=%lu, payload_size=%lu, remain=%lu/%ld)\n",
                hwport_xfrm_name((unsigned int)s_nlmsghdr->nlmsg_type),
                (unsigned long)s_nlmsghdr->nlmsg_type,
                (unsigned long)s_nlmsghdr->nlmsg_type,
                (unsigned long)s_nlmsghdr->nlmsg_flags,
                (s_nlmsghdr->nlmsg_flags) ? "" : "<NONE FLAGS>",
#if defined(NLM_F_REQUEST)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_REQUEST) == NLM_F_REQUEST) ? "{REQUEST}" : "",
#else
                "",
#endif
#if defined(NLM_F_MULTI)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_MULTI) == NLM_F_MULTI) ? "{MULTI}" : "",
#else
                "",
#endif
#if defined(NLM_F_ACK)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_ACK) == NLM_F_ACK) ? "{ACK}" : "",
#else
                "",
#endif
#if defined(NLM_F_ECHO)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_ECHO) == NLM_F_ECHO) ? "{ECHO}" : "",
#else
                "",
#endif
#if defined(NLM_F_DUMP_INTR)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_DUMP_INTR) == NLM_F_DUMP_INTR) ? "{DUMP_INTR}" : "",
#else
                "",
#endif
#if defined(NLM_F_ROOT)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_ROOT) == NLM_F_ROOT) ? "{ROOT}" : "",
#else
                "",
#endif
#if defined(NLM_F_MATCH)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_MATCH) == NLM_F_MATCH) ? "{MATCH}" : "",
#else
                "",
#endif
#if defined(NLM_F_ATOMIC)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_ATOMIC) == NLM_F_ATOMIC) ? "{ATOMIC}" : "",
#else
                "",
#endif
#if defined(NLM_F_DUMP)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP) ? "{DUMP}" : "",
#else
                "",
#endif
#if defined(NLM_F_REPLACE)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_REPLACE) == NLM_F_REPLACE) ? "{REPLACE}" : "",
#else
                "",
#endif
#if defined(NLM_F_EXCL)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_EXCL) == NLM_F_EXCL) ? "{EXCL}" : "",
#else
                "",
#endif
#if defined(NLM_F_CREATE)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_CREATE) == NLM_F_CREATE) ? "{CREATE}" : "",
#else
                "",
#endif
#if defined(NLM_F_APPEND)
                ((s_nlmsghdr->nlmsg_flags & NLM_F_APPEND) == NLM_F_APPEND) ? "{APPEND}" : "",
#else
                "",
#endif
                (unsigned long)s_nlmsghdr->nlmsg_seq,
                (unsigned long)s_nlmsghdr->nlmsg_pid,
                (unsigned long)s_nlmsghdr->nlmsg_len,
                (unsigned long)s_payload_size,
                (unsigned long)s_msg_size,
                (long)s_recv_bytes
            );
            ++s_depth;

            switch(s_nlmsghdr->nlmsg_type) {
#if defined(NLMSG_NOOP)
                case NLMSG_NOOP:
                    s_message_size = (size_t)0u;
                    s_output_offset += hwport_dump(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        s_payload,
                        s_payload_size
                    );
                    break;
#endif
#if defined(NLMSG_ERROR)
                case NLMSG_ERROR:
                    s_message_size = (size_t)0u;
                    s_output_offset += hwport_dump(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        s_payload,
                        s_payload_size
                    );

                    s_is_break = 1;
                    break;
#endif
#if defined(NLMSG_DONE)
                case NLMSG_DONE:
                    s_message_size = (size_t)0u;
                    s_output_offset += hwport_dump(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        s_payload,
                        s_payload_size
                    );

                    s_is_break = 1;
                    break;
#endif
#if defined(NLMSG_OVERRUN)
                case NLMSG_OVERRUN:
                    s_message_size = (size_t)0u;
                    s_output_offset += hwport_dump(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        s_payload,
                        s_payload_size
                    );

                    s_is_break = 1;
                    break;
#endif
#if defined(XFRM_MSG_NEWSA)
                case XFRM_MSG_NEWSA: /* struct xfrm_usersa_info */
                    s_message_size = sizeof(struct xfrm_usersa_info);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_xfrm_usersa_info(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (struct xfrm_usersa_info *)s_payload
                    );
                    break;
#endif
#if defined(XFRM_MSG_DELSA)
                case XFRM_MSG_DELSA: /* struct xfrm_usersa_id */
                    s_message_size = sizeof(struct xfrm_usersa_id);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_xfrm_usersa_id(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (struct xfrm_usersa_id *)s_payload
                    );
                    break;
#endif
#if defined(XFRM_MSG_GETSA)
                case XFRM_MSG_GETSA: /* struct xfrm_usersa_id */
                    s_message_size = sizeof(struct xfrm_usersa_id);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_xfrm_usersa_id(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (struct xfrm_usersa_id *)s_payload
                    );
                    break;
#endif
#if defined(XFRM_MSG_NEWPOLICY)
                case XFRM_MSG_NEWPOLICY: /* struct xfrm_userpolicy_info */
                    s_message_size = sizeof(struct xfrm_userpolicy_info);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_xfrm_userpolicy_info(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (struct xfrm_userpolicy_info *)s_payload
                    );
                    break;
#endif
#if defined(XFRM_MSG_DELPOLICY)
                case XFRM_MSG_DELPOLICY: /* struct xfrm_userpolicy_id */
                    s_message_size = sizeof(struct xfrm_userpolicy_id);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_xfrm_userpolicy_id(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (struct xfrm_userpolicy_id *)s_payload
                    );
                    break;
#endif
#if defined(XFRM_MSG_GETPOLICY)
                case XFRM_MSG_GETPOLICY: /* struct xfrm_userpolicy_id */
                    s_message_size = sizeof(struct xfrm_userpolicy_id);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_xfrm_userpolicy_id(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (struct xfrm_userpolicy_id *)s_payload
                    );
                    break;
#endif
#if defined(XFRM_MSG_ALLOCSPI)
                case XFRM_MSG_ALLOCSPI: /* struct xfrm_userspi_info */
                    s_message_size = sizeof(struct xfrm_userspi_info);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_xfrm_userspi_info(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (struct xfrm_userspi_info *)s_payload
                    );
                    break;
#endif
#if defined(XFRM_MSG_ACQUIRE)
                case XFRM_MSG_ACQUIRE: /* struct xfrm_user_acquire */
                    s_message_size = sizeof(struct xfrm_user_acquire);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_xfrm_user_acquire(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (struct xfrm_user_acquire *)s_payload
                    );
                    break;
#endif
#if defined(XFRM_MSG_EXPIRE)
                case XFRM_MSG_EXPIRE: /* struct xfrm_user_expire */
                    s_message_size = sizeof(struct xfrm_user_expire);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_xfrm_user_expire(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (struct xfrm_user_expire *)s_payload
                    );
                    break;
#endif
#if defined(XFRM_MSG_UPDPOLICY)
                case XFRM_MSG_UPDPOLICY: /* struct xfrm_userpolicy_info */
                    s_message_size = sizeof(struct xfrm_userpolicy_info);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_xfrm_userpolicy_info(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (struct xfrm_userpolicy_info *)s_payload
                    );
                    break;
#endif
#if defined(XFRM_MSG_UPDSA)
                case XFRM_MSG_UPDSA: /* struct xfrm_usersa_info */
                    s_message_size = sizeof(struct xfrm_usersa_info);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_xfrm_usersa_info(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (struct xfrm_usersa_info *)s_payload
                    );
                    break;
#endif
#if defined(XFRM_MSG_POLEXPIRE)
                case XFRM_MSG_POLEXPIRE: /* struct xfrm_user_polexpire */
                    s_message_size = sizeof(struct xfrm_user_polexpire);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_xfrm_user_polexpire(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (struct xfrm_user_polexpire *)s_payload
                    );
                    break;
#endif
#if defined(XFRM_MSG_FLUSHSA)
                case XFRM_MSG_FLUSHSA: /* struct xfrm_usersa_flush */
                    s_message_size = sizeof(struct xfrm_usersa_flush);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_xfrm_usersa_flush(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (struct xfrm_usersa_flush *)s_payload
                    );
                    break;
#endif
#if defined(XFRM_MSG_FLUSHPOLICY)
                case XFRM_MSG_FLUSHPOLICY: /* x */
                    s_message_size = (size_t)0u;
                    s_output_offset += hwport_dump(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        s_payload,
                        s_payload_size
                    );
                    break;
#endif
#if defined(XFRM_MSG_NEWAE)
                case XFRM_MSG_NEWAE: /* struct xfrm_aevent_id */
                    s_message_size = sizeof(struct xfrm_aevent_id);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_xfrm_aevent_id(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (struct xfrm_aevent_id *)s_payload
                    );
                    break;
#endif
#if defined(XFRM_MSG_GETAE)
                case XFRM_MSG_GETAE: /* struct xfrm_aevent_id */
                    s_message_size = sizeof(struct xfrm_aevent_id);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_xfrm_aevent_id(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (struct xfrm_aevent_id *)s_payload
                    );
                    break;
#endif
#if defined(XFRM_MSG_REPORT)
                case XFRM_MSG_REPORT: /* struct xfrm_user_report */
                    s_message_size = sizeof(struct xfrm_user_report);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_xfrm_user_report(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (struct xfrm_user_report *)s_payload
                    );
                    break;
#endif
#if defined(XFRM_MSG_MIGRATE)
                case XFRM_MSG_MIGRATE: /* struct xfrm_userpolicy_id */
                    s_message_size = sizeof(struct xfrm_userpolicy_id);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_xfrm_userpolicy_id(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (struct xfrm_userpolicy_id *)s_payload
                    );
                    break;
#endif
#if defined(XFRM_MSG_NEWSADINFO)
                case XFRM_MSG_NEWSADINFO: /* u32 */ 
                    s_message_size = sizeof(__u32);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_xfrm_usersad_info(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (__u32 *)s_payload
                    );
                    break;
#endif
#if defined(XFRM_MSG_GETSADINFO)
                case XFRM_MSG_GETSADINFO:  /* u32 */
                    s_message_size = sizeof(__u32);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_xfrm_usersad_info(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (__u32 *)s_payload
                    );
                    break;
#endif
#if defined(XFRM_MSG_NEWSPDINFO)
                case XFRM_MSG_NEWSPDINFO: /* u32 */
                    s_message_size = sizeof(__u32);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_xfrm_userspd_info(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (__u32 *)s_payload
                    );
                    break;
#endif
#if defined(XFRM_MSG_GETSPDINFO)
                case XFRM_MSG_GETSPDINFO: /* u32 */
                    s_message_size = sizeof(__u32);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_xfrm_userspd_info(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (__u32 *)s_payload
                    );
                    break;
#endif
#if defined(XFRM_MSG_MAPPING)
                case XFRM_MSG_MAPPING: /* struct xfrm_user_mapping */
                    s_message_size = sizeof(struct xfrm_user_mapping);
                    if(s_payload_size < s_message_size) {
                        s_output_offset += hwport_dump(
                            (char *)(&s_output_buffer[s_output_offset]),
                            s_output_buffer_size - s_output_offset,
                            s_depth,
                            s_payload,
                            s_payload_size
                        );
                        break;
                    }

                    s_output_offset += hwport_dump_xfrm_user_mapping(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        (struct xfrm_user_mapping *)s_payload
                    );
                    break;
#endif
                default:
                    s_message_size = (size_t)0u;
                    s_output_offset += hwport_dump(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth,
                        s_payload,
                        s_payload_size
                    );
                    break;
            }

            if(s_payload_size > s_message_size) { /* attribute parsing */
                static const char *cg_xfrma_name_table[] = {
                    "XFRMA_UNSPEC",
                    "XFRMA_ALG_AUTH",         /* struct xfrm_algo */
                    "XFRMA_ALG_CRYPT",        /* struct xfrm_algo */
                    "XFRMA_ALG_COMP",         /* struct xfrm_algo */
                    "XFRMA_ENCAP",            /* struct xfrm_algo + struct xfrm_encap_tmpl */
                    "XFRMA_TMPL",             /* 1 or more struct xfrm_user_tmpl */
                    "XFRMA_SA",               /* struct xfrm_usersa_info  */
                    "XFRMA_POLICY",           /* struct xfrm_userpolicy_info */
                    "XFRMA_SEC_CTX",          /* struct xfrm_sec_ctx */
                    "XFRMA_LTIME_VAL",
                    "XFRMA_REPLAY_VAL",
                    "XFRMA_REPLAY_THRESH",
                    "XFRMA_ETIMER_THRESH",
                    "XFRMA_SRCADDR",          /* xfrm_address_t */
                    "XFRMA_COADDR",           /* xfrm_address_t */
                    "XFRMA_LASTUSED",         /* unsigned long  */
                    "XFRMA_POLICY_TYPE",      /* struct xfrm_userpolicy_type */
                    "XFRMA_MIGRATE",
                    "XFRMA_ALG_AEAD",         /* struct xfrm_algo_aead */
                    "XFRMA_KMADDRESS",        /* struct xfrm_user_kmaddress */
                    "XFRMA_ALG_AUTH_TRUNC",   /* struct xfrm_algo_auth */
                    "XFRMA_MARK",             /* struct xfrm_mark */
                    "XFRMA_TFCPAD",           /* __u32 */
                    "XFRMA_REPLAY_ESN_VAL",   /* struct xfrm_replay_esn */
                    "XFRMA_SA_EXTRA_FLAGS",   /* __u32 */
                    "XFRMA_PROTO",            /* __u8 */
                    "XFRMA_ADDRESS_FILTER",   /* struct xfrm_address_filter */
                    "XFRMA_PAD"
                };
                size_t s_attr_window_size;
                struct nlattr *s_nlattr;
                size_t s_attr_size;
                void *s_attr_payload;

                s_attr_window_size = s_payload_size - s_message_size;
                
                for(s_nlattr = (struct nlattr *)(((unsigned char *)s_payload) + NLMSG_ALIGN(s_message_size));(s_attr_window_size >= sizeof(struct nlattr)) && (s_nlattr->nla_len >= sizeof(struct nlattr)) && (s_nlattr->nla_len <= s_attr_window_size);s_attr_window_size -= NLA_ALIGN(s_nlattr->nla_len), s_nlattr = (struct nlattr *)(((unsigned char *)s_nlattr) + NLA_ALIGN(s_nlattr->nla_len))) {
                    s_attr_payload = (void *)(((unsigned char *)s_nlattr) + NLA_HDRLEN);
                    s_attr_size = s_nlattr->nla_len;

                    s_output_offset += hwport_dump_space(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth + 1
                    );
                    s_output_offset += (size_t)snprintf(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        "attribute: type=%04lu(%s), len=%lu\n",
                        (unsigned long)s_nlattr->nla_type,
                        (s_nlattr->nla_type < (sizeof(cg_xfrma_name_table) / sizeof(const char *))) ? cg_xfrma_name_table[s_nlattr->nla_type] : "UNKNOWN",
                        (unsigned long)s_nlattr->nla_len
                    );
                    s_output_offset += hwport_dump(
                        (char *)(&s_output_buffer[s_output_offset]),
                        s_output_buffer_size - s_output_offset,
                        s_depth + 2,
                        s_attr_payload, 
                        s_attr_size
                    );
                }
                s_output_offset += hwport_dump_space(
                    (char *)(&s_output_buffer[s_output_offset]),
                    s_output_buffer_size - s_output_offset,
                    s_depth + 1
                );
                s_output_offset += (size_t)snprintf(
                    (char *)(&s_output_buffer[s_output_offset]),
                    s_output_buffer_size - s_output_offset,
                    "end of attribute (remain=%lu/%lu)\n",
                    (unsigned long)s_attr_window_size,
                    (unsigned long)(s_payload_size - s_message_size)
                );
            }

            if((s_output_offset > ((size_t)0u)) && (s_output_offset > (s_output_buffer_size >> 1))) { /* print message buffer (when many buffered) */
                (void)hwport_output_puts((const char *)(&s_output_buffer[0]));
                s_output_offset = (size_t)0u;
            }
        }

        if(s_output_offset > ((size_t)0u)) { /* print message buffer */
            (void)hwport_output_puts((const char *)(&s_output_buffer[0]));
            s_output_offset = (size_t)0u;
        }
    }

    free(s_buffer);
    (void)close(s_socket);

    return(EXIT_SUCCESS);
}

/* vim: set expandtab: */
/* End of source */
