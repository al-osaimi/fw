

#include "firewall.h"

#define FIREWALL_MAX_ENTRIES (10) /**< Defines the size of FW entries in the FW table. */

#define FW_NR_NETIFS (1) /**< Defines the number of network interfaces. This is used to reserve space for db_netif_struct's */

#define FIREWALL_FREE (0) /**< Tells you that an FW entry is free */
#define FIREWALL_USED (1) /**< Tells you that an FW entry is used */

#define POLICY_APPLY (0)   /**< Defines that the policy for this FW entry means: apply Friewall */
#define POLICY_BYPASS (1)  /**< Defines that the policy for this FW entry means: bypass Friewall */
#define POLICY_DISCARD (2) /**< Defines that the policy for this FW entry means: the packet must be discarded */

typedef struct rule_entry_struct rule_entry; /**< Security Association Database entry */

/** \struct sa_entry_struct
 * Holds all the values used by an FW entry
 */
struct rule_entry_struct
{
    __u32 src;          /**< IP source address */
    __u32 src_netaddr;  /**< net mask for source address */
    __u32 dest;         /**< IP destination address */
    __u32 dest_netaddr; /**< net mask for the destination address */
    __u8 protocol;      /**< the transport layer protocol */
    __u16 src_port;     /**< source port number */
    __u16 dest_port;    /**< destination port number */
    __u8 policy;        /**< defines how this packet must be processed */
    rule_entry *next;   /**< pointer to the next table entry*/
    rule_entry *prev;   /**< pointer to the previous table entry */
    __u8 use_flag;      /**< tells whether the entry is free or not */
};

typedef struct rule_table_struct
{
    rule_entry *table; /**< Pointer to the table data. This is pointer to an array of rule_entries */
    rule_entry *first; /**< Pointer to the first entry in the table */
    rule_entry *last;  /**< Pointer to the last entry in the table */
    int size;          /**< Number of usable elements in the table data */
} rule_table;

typedef struct db_set_netif_struct
{
    rule_table inbound_spd;  /**< inbound SPD */
    rule_table outbound_spd; /**< outbound SPD */
    __u8 use_flag;           /**< tells whether the entry is free or not */
} db_set_netif;

#define FW_ENTRY(s1, s2, s3, s4, sn1, sn2, sn3, sn4, d1, d2, d3, d4, dn1, dn2, dn3, dn4, proto, src_port, dest_port, policy, sa_ptr) \
    IPSEC_IP4_ADDR_NET(s1, s2, s3, s4),                                                                                              \
        IPSEC_IP4_ADDR_NET(sn1, sn2, sn3, sn4),                                                                                      \
        IPSEC_IP4_ADDR_NET(d1, d2, d3, d4),                                                                                          \
        IPSEC_IP4_ADDR_NET(dn1, dn2, dn3, dn4),                                                                                      \
        proto, IPSEC_HTONS(src_port), IPSEC_HTONS(dest_port), policy, sa_ptr, 0, 0,                                                  \
        FIREWALL_USED /**< helps to statically configure the SPD entries */

#define EMPTY_FW_ENTRY       \
    {                        \
        0, 0, 0, 0, 0, 0,    \
            0, FIREWALL_FREE \
    } /**< empty, unconfigured FW entry */

/* FW functions */
db_set_netif *fw_rule_load_dbs(rule_entry *inbound_rule_data, rule_entry *outbound_rule_data);

fw_status fw_rule_release_dbs(db_set_netif *dbs);

rule_entry *fw_rule_get_free(rule_table *table);

rule_entry *fw_rule_add(__u32 src, __u32 src_net, __u32 dst,
                        __u32 dst_net, __u8 proto, __u16 src_port,
                        __u16 dst_port, __u8 policy, rule_table *table);

fw_status fw_rule_flush(rule_table *table, rule_entry *def_entry);

fw_status fw_rule_del(rule_entry *entry, rule_table *table);

rule_entry *fw_rule_lookup(ip_header *header, rule_table *table);

void fw_rule_print_single(rule_entry *entry);

void fw_rule_print(rule_table *table);