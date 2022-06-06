

#include "firewall.h"

db_set_netif db_sets[FW_NR_NETIFS];

typedef struct transport_ip_struct
{
    ip_header ip; /**< IPv4 header */
    union
    {
        tcp_header tcp; /**< TCP header */
        udp_header udp; /**< UDP header */
    } transport__header;
} transport_in_ip;

/**
 * Flushes an SPD table and sets a new default entry. The default entry allows to keep
 * a door open for IKE.
 *
 * @param table			pointer to the SPD table
 * @param def_entry 	pointer to the default entry
 * @return IPSEC_STATUS_SUCCESS if the flush was successful
 * @return IPSEC_STATUS_FAILURE if the flush failed
 */
fw_status fw_rule_flush(rule_table *table, rule_entry *def_entry)
{
    memset(table->table, 0, sizeof(rule_entry) * FIREWALL_MAX_ENTRIES);
    table->first = NULL;
    table->first = NULL;

    if (fw_rule_add(def_entry->src,
                    def_entry->src_netaddr,
                    def_entry->dest,
                    def_entry->dest_netaddr,
                    def_entry->protocol,
                    def_entry->src_port,
                    def_entry->dest_port,
                    def_entry->policy,
                    table) == NULL)
        return IPSEC_STATUS_FAILURE;

    return IPSEC_STATUS_SUCCESS;
}

db_set_netif *fw_rule_load_dbs(rule_entry *inbound_spd_data, rule_entry *outbound_spd_data)
{
    int netif;
    int index;
    rule_entry *sp, *sp_next, *sp_prev;

    IPSEC_LOG_TRC(IPSEC_TRACE_ENTER,
                  "fw_rule_load_dbs",
                  ("inbound_spd_data=%p, outbound_spd_data=%p",
                   (void *)inbound_spd_data, (void *)outbound_spd_data));

    /* get free entry */
    for (netif = 0; netif < FW_NR_NETIFS; netif++)
    {
        if (db_sets[netif].use_flag == FIREWALL_FREE)
            break;
    }
    if (netif >= FW_NR_NETIFS)
    {
        IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "fw_rule_load_dbs", ("%p", (void *)NULL));
        return NULL;
    }

    /* index points now the a free entry which is filled with the initialization data */
    db_sets[netif].inbound_spd.table = inbound_spd_data;
    db_sets[netif].outbound_spd.table = outbound_spd_data;

    db_sets[netif].use_flag = FIREWALL_USED;

    /* set none used entries from the tables to FREE */
    for (index = 0; index < FIREWALL_MAX_ENTRIES; index++)
        if (db_sets[netif].inbound_spd.table[index].use_flag != FIREWALL_USED)
            db_sets[netif].inbound_spd.table[index].use_flag = FIREWALL_FREE;

    for (index = 0; index < FIREWALL_MAX_ENTRIES; index++)
        if (db_sets[netif].outbound_spd.table[index].use_flag != FIREWALL_USED)
            db_sets[netif].outbound_spd.table[index].use_flag = FIREWALL_FREE;

    /* inbound spd data */
    sp = inbound_spd_data;
    /* if first entry is FIREWALL_FREE, then there is nothing */
    if (sp->use_flag == FIREWALL_USED)
    {
        db_sets[netif].inbound_spd.first = sp;

        if ((sp + 1)->use_flag == FIREWALL_USED)
        {
            sp_next = (sp + 1);
        }
        else
        {
            sp_next = NULL;
        }

        for (index = 0, sp_prev = NULL;
             (index < FIREWALL_MAX_ENTRIES) && (sp[index + 1].use_flag == FIREWALL_USED);
             sp_prev = &sp[index], sp_next = &sp[index + 2], index++)
        {
            sp[index].prev = sp_prev;
            sp[index].next = sp_next;
        }

        sp[index].next = NULL;
        db_sets[netif].inbound_spd.last = &sp[index];
    }
    else
    {
        printf("there was no inbound data %d\n", sp->use_flag);
        db_sets[netif].inbound_spd.first = NULL;
        db_sets[netif].inbound_spd.last = NULL;
    }

    /* outbound spd data */
    sp = outbound_spd_data;
    /* if first entry is FIREWALL_FREE, then there is nothing */
    if (sp->use_flag == FIREWALL_USED)
    {
        db_sets[netif].outbound_spd.first = sp;

        if ((sp + 1)->use_flag == FIREWALL_USED)
        {
            sp_next = (sp + 1);
        }
        else
        {
            sp_next = NULL;
        }

        for (index = 0, sp_prev = NULL;
             (index < FIREWALL_MAX_ENTRIES) && (sp[index + 1].use_flag == FIREWALL_USED);
             sp_prev = &sp[index], sp_next = &sp[index + 2], index++)
        {
            sp[index].prev = sp_prev;
            sp[index].next = sp_next;
        }

        sp[index].next = NULL;
        db_sets[netif].outbound_spd.last = &sp[index];
    }
    else
    {
        printf("there was no outbound data\n");
        db_sets[netif].outbound_spd.first = NULL;
        db_sets[netif].outbound_spd.last = NULL;
    }

    IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "fw_rule_load_dbs", ("&db_sets[netif] = %p", &db_sets[netif]));
    return &db_sets[netif];
}

rule_entry *fw_rule_add(__u32 src, __u32 src_net, __u32 dst, __u32 dst_net, __u8 proto, __u16 src_port, __u16 dst_port, __u8 policy, rule_table *table)
{
    rule_entry *free_entry;
    rule_entry *tmp_entry;
    int table_size;

    IPSEC_LOG_TRC(IPSEC_TRACE_ENTER,
                  "fw_rule_add",
                  ("src=%lu, src_net=%lu, dst=%lu, dst_net=%lu, proto=%u, src_port=%u, dst_port=%u, policy=%u, table=%p",
                   src, src_net, dst, dst_net, proto, src_port, dst_port, policy, (void *)table));

    table_size = table->size;

    free_entry = fw_rule_get_free(table);
    if (free_entry == NULL)
    {
        IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "fw_rule_add", ("%p", (void *)NULL));
        return NULL;
    }

    /* add the fields to the entry */
    free_entry->src = src;
    free_entry->src_netaddr = src_net;
    free_entry->dest = dst;
    free_entry->dest_netaddr = dst_net;

    free_entry->protocol = proto;
    free_entry->src_port = src_port;
    free_entry->dest_port = dst_port;
    free_entry->policy = policy;

    free_entry->use_flag = FIREWALL_USED;

    /* re-link entry */
    /** @todo this part needs to be rewritten when an order is introduced */

    /* if added first entry in array */
    if (table->first == NULL)
    {
        table->first = free_entry;
        table->first->next = NULL;
        table->first->prev = NULL;
        table->last = free_entry;
    }
    else
    {
        /* go till end of list */
        for (tmp_entry = table->first; tmp_entry->next != NULL; tmp_entry = tmp_entry->next)
        {
        }

        /* inset at end */
        free_entry->prev = tmp_entry;
        tmp_entry->next = free_entry;
        free_entry->next = NULL;
    }

    IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "fw_rule_add", ("free_entry=%p", (void *)free_entry));
    return free_entry;
}

rule_entry *fw_rule_get_free(rule_table *table)
{
    int index;
    IPSEC_LOG_TRC(IPSEC_TRACE_ENTER,
                  "ipsec_spd_get_free",
                  ("table=%p",
                   (void *)table));

    /* find first free entry */
    for (index = 0; index < FIREWALL_MAX_ENTRIES; index++)
    {
        if (table->table[index].use_flag == FIREWALL_FREE)
            break;
    }
    /* if no free entry */
    if (index >= FIREWALL_MAX_ENTRIES)
    {
        return NULL;
    }

    IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_spd_get_free", ("&table->table[index] = %p", &table->table[index]));
    return &table->table[index];
}
/**
 * Deletes an Security Policy from an SPD table.
 *
 * This function is simple. If the pointer is within the range of the table, then
 * the entry is cleared. If the pointer does not match, nothing happens.
 *
 * @param entry Pointer to the SPD entry which needs to be deleted
 * @param table Pointer to the SPD table
 *
 * @return IPSEC_STATUS_SUCCESS	entry was deleted properly
 * @return IPSEC_STATUS_FAILURE entry could not be deleted because not found, or invalid pointer
 * @todo right now there is no special order implemented, maybe this is needed
 */
fw_status fw_rule_del(rule_entry *entry, rule_table *table)
{
    rule_entry *next_ptr;
    rule_entry *prev_ptr;

    IPSEC_LOG_TRC(IPSEC_TRACE_ENTER,
                  "fw_rule_del",
                  ("entry=%p, table=%p",
                   (void *)entry, (void *)table));

    /* check range */
    if ((entry >= table->table) && (entry <= (table->table + (FIREWALL_MAX_ENTRIES * sizeof(rule_entry)))))
    {
        /* first clear associated SA if there is one */
        /**@todo probably the SA should also be deleted */

        /* relink table */

        if (entry->use_flag != FIREWALL_USED)
        {
            IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "fw_rule_del", ("return = %d", IPSEC_STATUS_FAILURE));
            return IPSEC_STATUS_FAILURE;
        }

        /* relink previous with next */
        prev_ptr = entry->prev;
        next_ptr = entry->next;
        if (prev_ptr)
            prev_ptr->next = next_ptr;
        if (next_ptr)
            next_ptr->prev = prev_ptr;

        /* if removed last entry */
        if (entry->next == NULL)
        {
            table->last == entry->prev;
        }

        /* if removed first entry */
        if (entry == table->first)
        {
            table->first = entry->next;
        }

        /* clear field */
        entry->use_flag = FIREWALL_FREE;

        IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "fw_rule_del", ("return = %d", IPSEC_STATUS_SUCCESS));
        return IPSEC_STATUS_SUCCESS;
    }

    IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "fw_rule_del", ("return = %d", IPSEC_STATUS_FAILURE));
    return IPSEC_STATUS_FAILURE;
}

/**
 * Returns an pointer to an SPD entry which matches the packet.
 *
 * Inbound packets must be checked against the inbound SPD and outbound
 * packets must be checked against the outbound SPD.
 *
 * Implementation
 *
 * This function checks all the selector fields of the SPD table. The port numbers
 * are only checked if the protocol is TCP or UDP.
 * An entry which has a value of 0 is the same as the '*' which means everything.
 *
 * @param	header	Pointer to an IP packet which is checked
 * @param 	table	Pointer to the SPD inbound/outbound table
 * @return 	Pointer to the matching SPD entry
 * @return 	NULL if no entry matched
 * @todo port checking should be implemnted also
 */
rule_entry *fw_rule_lookup(ip_header *header, rule_table *table)
{
    rule_entry *tmp_entry;
    transport_in_ip *ip;

    IPSEC_LOG_TRC(IPSEC_TRACE_ENTER,
                  "fw_rule_lookup",
                  ("header=%p, table=%p",
                   (void *)header, (void *)table));

    ip = (transport_in_ip *)header;

    /* compare and return when all fields match */
    for (tmp_entry = table->first; tmp_entry != NULL; tmp_entry = tmp_entry->next)
    {
        if (ipsec_ip_addr_maskcmp(header->src, tmp_entry->src, tmp_entry->src_netaddr))
        {
            if (ipsec_ip_addr_maskcmp(header->dest, tmp_entry->dest, tmp_entry->dest_netaddr))
            {
                if ((tmp_entry->protocol == 0) || tmp_entry->protocol == header->protocol)
                {
                    if (header->protocol == IPSEC_PROTO_TCP)
                    {
                        if ((tmp_entry->src_port == 0) || (tmp_entry->src_port == ip->transport__header.tcp.src))
                            if ((tmp_entry->dest_port == 0) || (tmp_entry->dest_port == ip->transport__header.tcp.dest))
                            {
                                IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "fw_rule_lookup", ("tmp_entry = %p", (void *)tmp_entry));
                                return tmp_entry;
                            }
                    }
                    else if (header->protocol == IPSEC_PROTO_UDP)
                    {
                        if ((tmp_entry->src_port == 0) || (tmp_entry->src_port == ip->transport__header.udp.src))
                            if ((tmp_entry->dest_port == 0) || (tmp_entry->dest_port == ip->transport__header.udp.dest))
                            {
                                IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "fw_rule_lookup", ("tmp_entry = %p", (void *)tmp_entry));
                                return tmp_entry;
                            }
                    }
                    else
                    {
                        IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "fw_rule_lookup", ("tmp_entry = %p", (void *)tmp_entry));
                        return tmp_entry;
                    }
                }
            }
        }
    }
    IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "fw_rule_lookup", ("return = %p", (void *)NULL));
    return NULL;
}

/**
 * Prints a single rule entry.
 *
 * @param entry pointer to the SPD entry
 * @return void
 */
void fw_rule_print_single(rule_entry *entry)
{
    char log_message[IPSEC_LOG_MESSAGE_SIZE + 1];
    char ip_addr1[IPSEC_LOG_MESSAGE_SIZE + 1];
    char ip_addr2[IPSEC_LOG_MESSAGE_SIZE + 1];
    char ip_addr3[IPSEC_LOG_MESSAGE_SIZE + 1];
    char ip_addr4[IPSEC_LOG_MESSAGE_SIZE + 1];
    char protocol[10 + 1];
    char policy[10 + 1];

    strcpy(ip_addr1, ipsec_inet_ntoa(entry->src));
    strcpy(ip_addr2, ipsec_inet_ntoa(entry->src_netaddr));
    strcpy(ip_addr3, ipsec_inet_ntoa(entry->dest));
    strcpy(ip_addr4, ipsec_inet_ntoa(entry->dest_netaddr));

    switch (entry->protocol)
    {
    case IPSEC_PROTO_TCP:
        strcpy(protocol, " TCP");
        break;
    case IPSEC_PROTO_UDP:
        strcpy(protocol, " UDP");
        break;
    case IPSEC_PROTO_AH:
        strcpy(protocol, "  AH");
        break;
    case IPSEC_PROTO_ESP:
        strcpy(protocol, " ESP");
        break;
    case IPSEC_PROTO_ICMP:
        strcpy(protocol, "ICMP");
        break;
    default:
        sprintf(protocol, "%4d", entry->protocol);
    }

    switch (entry->policy)
    {
    case POLICY_APPLY:
        strcpy(policy, "  APPLY");
        break;
    case POLICY_BYPASS:
        strcpy(policy, " BYPASS");
        break;
    case POLICY_DISCARD:
        strcpy(policy, "DISCARD");
        break;
    default:
        strcpy(policy, "UNKNOWN");
    }

    sprintf(log_message, "%15s/%15s   %15s/%15s %3s %5u %5u    %7s",
            ip_addr1, ip_addr2, ip_addr3, ip_addr4,
            protocol,
            ipsec_ntohs(entry->src_port),
            ipsec_ntohs(entry->dest_port),
            policy);

    printf("    %s\n", log_message);

    return;
}

/**
 * Prints a Security Policy Database.
 *
 * @param table pointer to the SPD table
 * @return void
 */
void fw_rule_print(rule_table *table)
{
    rule_entry *tmp_ptr;

    IPSEC_LOG_MSG("FW_rule_print", ("Printf Firewall Rule Database"));
    printf("      src-addr/net-addr               dst-addr/net-addr                proto prt:src/dest  policy  \n");

    if (table->first == NULL)
    {
        printf("      Firewall table is empty\n");
    }

    /* loop over all entries and print them */
    for (tmp_ptr = table->first; tmp_ptr != NULL; tmp_ptr = tmp_ptr->next)
    {
        fw_rule_print_single(tmp_ptr);
    }

    return;
}