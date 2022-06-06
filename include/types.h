

#ifndef __IPSEC_TYPES_H__
#define __IPSEC_TYPES_H__

#include <stdint.h>
#include <stdlib.h>

typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef signed short __s16;
typedef unsigned long __u32;
typedef signed long __s32;

typedef enum ipsec_audit_list
{                                  /** This value is returned if ... */
  IPSEC_AUDIT_SUCCESS = 0,         /**<  processing was successful */
  IPSEC_AUDIT_NOT_IMPLEMENTED = 1, /**<  the function is already there but the functionality is not yet implemented */
  IPSEC_AUDIT_FAILURE = 2,         /**<  failure  */
  IPSEC_AUDIT_APPLY = 3,           /**<  packet must be processed by IPsec */
  IPSEC_AUDIT_BYPASS = 4,          /**<  packet is forwarded (without IPsec processing) */
  IPSEC_AUDIT_DISCARD = 5,         /**<  packet must be dropped */
  IPSEC_AUDIT_SPI_MISMATCH = 6,    /**<  SPI does not match the SPD lookup */
  IPSEC_AUDIT_SEQ_MISMATCH = 7,    /**<  Sequence Number differs more than IPSEC_SEQ_MAX_WINDOW from the previous packets */
  IPSEC_AUDIT_POLICY_MISMATCH = 8  /**<  If a policy for an incoming IPsec packet does not specify APPLY */
} ipsec_audit;

typedef enum ipsec_status_list
{                                     /** This value is returned if ... */
  IPSEC_STATUS_SUCCESS = 0,           /**<  processing was successful */
  IPSEC_STATUS_NOT_IMPLEMENTED = -1,  /**<  the function is already there but the functionality is not yet implemented */
  IPSEC_STATUS_FAILURE = -2,          /**<  failure */
  IPSEC_STATUS_DATA_SIZE_ERROR = -3,  /**<  buffer is (unexpectedly) empty or haves wrong size */
  IPSEC_STATUS_NO_SPACE_IN_SPD = -4,  /**<  ipsec_spd_add() failed because there was no space left in SPD */
  IPSEC_STATUS_NO_POLICY_FOUND = -5,  /**<  no matching SPD policy was found */
  IPSEC_STATUS_NO_SA_FOUND = -6,      /**<  no matching SA was found */
  IPSEC_STATUS_BAD_PACKET = -7,       /**<  packet has a bad format or invalid fields */
  IPSEC_STATUS_BAD_PROTOCOL = -8,     /**<  SA has an unsupported protocol */
  IPSEC_STATUS_BAD_KEY = -9,          /**<  key is invalid or weak and was rejected */
  IPSEC_STATUS_TTL_EXPIRED = -10,     /**<  TTL value of a packet reached 0 */
  IPSEC_STATUS_NOT_INITIALIZED = -100 /**<  variables has never been initialized */
} fw_status;

typedef enum ipsec_ip_protocol_list
{                          /** IP protocol number for ... */
  IPSEC_PROTO_ICMP = 0x01, /**<  ICMP */
  IPSEC_PROTO_TCP = 0x06,  /**<  TCP  */
  IPSEC_PROTO_UDP = 0x11,  /**<  UDP  */
  IPSEC_PROTO_ESP = 0x32,  /**<  ESP  */
  IPSEC_PROTO_AH = 0x33    /**<  AH   */
} ipsec_ip_protocol;

typedef struct ipsec_ip_hdr_struct
{
  __u8 v_hl;     /**< version / header length        */
  __u8 tos;      /**< type of service                */
  __u16 len;     /**< total length                   */
  __u16 id;      /**< identification                 */
  __u16 offset;  /**< fragment offset field / flags  */
  __u8 ttl;      /**< time to live                   */
  __u8 protocol; /**< protocol                       */
  __u16 chksum;  /**< checksum                       */
  __u32 src;     /**< source address                 */
  __u32 dest;    /**< destination address            */
} ip_header;

typedef struct ipsec_tcp_hdr_struct
{
  __u16 src;          /**< source port number             */
  __u16 dest;         /**< destination port number        */
  __u32 seqno;        /**< sequence number                */
  __u32 ackno;        /**< acknowledge number             */
  __u16 offset_flags; /**< offset /flags                  */
  __u16 wnd;          /**< window                         */
  __u16 chksum;       /**< checksum                       */
  __u16 urgp;         /**< urgent pointer                 */
} tcp_header;

typedef struct ipsec_udp_hdr_struct
{
  __u16 src;    /**< source port number             */
  __u16 dest;   /**< destination port number        */
  __u16 len;    /**< length of UDP header and data  */
  __u16 chksum; /**< checksum                       */
} udp_header;

#endif