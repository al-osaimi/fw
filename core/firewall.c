#include "firewall.h"

/**
 * IPsec input processing
 *
 * This function is called by the ipsec device driver when a packet arrives having AH or ESP in the
 * protocol field. A SA lookup gets the appropriate SA which is then passed to the packet processing
 * funciton ipsec_ah_check() or ipsec_esp_decapsulate(). After successfully processing an IPsec packet
 * an check together with an SPD lookup verifies if the packet was processed acording the right SA.
 *
 * @param  packet         pointer used to access the intercepted original packet
 * @param  packet_size    length of the intercepted packet
 * @param  payload_offset pointer used to return offset of the new IP packet relative to original packet pointer
 * @param  payload_size   pointer used to return total size of the new IP packet
 * @param  databases      Collection of all security policy databases for the active IPsec device
 * @return int 			  return status code
 */
int fw_input(unsigned char *packet, int packet_size,
             int *payload_offset, int *payload_size,
             db_set_netif *databases)
{
    int ret_val = IPSEC_STATUS_NOT_INITIALIZED; /* by default, the return value is undefined  */
    int dummy = packet_size;                    /* dummy operation to avoid compiler warnings */
    rule_entry *rule;
    ip_header *ip;
    ip_header *inner_ip;

    IPSEC_LOG_TRC(IPSEC_TRACE_ENTER,
                  "fw_input",
                  ("*packet=%p, packet_size=%d, len=%u, *payload_offset=%d, *payload_size=%d databases=%p",
                   (void *)packet, packet_size, (int)*payload_offset, (int)*payload_size, (void *)databases));

    IPSEC_DUMP_BUFFER(" INBOUND ESP or AH:", packet, 0, packet_size);

    ip = (ip_header *)packet;

    inner_ip = (ip_header *)(((unsigned char *)ip) + *payload_offset);

    rule = fw_rule_lookup(inner_ip, &databases->inbound_spd);

    if (rule == NULL)
    {
        IPSEC_LOG_AUD("fw_input", IPSEC_AUDIT_FAILURE, ("no matching SPD found"));
        IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "fw_input", ("ret_val=%d", IPSEC_STATUS_FAILURE));
        return IPSEC_STATUS_FAILURE;
    }

    if (rule->policy == POLICY_DISCARD)
    {

        IPSEC_LOG_AUD("fw_input", IPSEC_AUDIT_SPI_MISMATCH, ("POLICY_DISCARD"));
        IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "fw_input", ("return = %d", IPSEC_AUDIT_SPI_MISMATCH));
        return IPSEC_STATUS_FAILURE;
    }
    else if (rule->policy == POLICY_BYPASS)
    {
        IPSEC_LOG_AUD("fw_input", IPSEC_AUDIT_POLICY_MISMATCH, ("POLICY_BYPASS"));
    }

    IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "fw_input", ("return = %d", IPSEC_STATUS_SUCCESS));
    return IPSEC_STATUS_SUCCESS;
}

// /**
//  *  IPsec output processing
//  *
//  * This function is called when outbound packets need IPsec processing. Depending the SA, passed via
//  * the SPD entry ipsec_ah_check() and ipsec_esp_encapsulate() is called to encapsulate the packet in a
//  * IPsec header.
//  *
//  * @param  packet         pointer used to access the intercepted original packet
//  * @param  packet_size    length of the intercepted packet
//  * @param  payload_offset pointer used to return offset of the new IP packet relative to original packet pointer
//  * @param  payload_size   pointer used to return total size of the new IP packet
//  * @param  src            IP address of the local tunnel start point (external IP address)
//  * @param  dst            IP address of the remote tunnel end point (external IP address)
//  * @param  rule            pointer to security policy database where the rules for IPsec processing are stored
//  * @return int 			  return status code
//  */
// int ipsec_output(unsigned char *packet, int packet_size, int *payload_offset, int *payload_size,
//                  __u32 src, __u32 dst, spd_entry *rule)
// {
//     int ret_val = IPSEC_STATUS_NOT_INITIALIZED; /* by default, the return value is undefined */
//     ip_header *ip;

//     IPSEC_LOG_TRC(IPSEC_TRACE_ENTER,
//                   "ipsec_output",
//                   ("*packet=%p, packet_size=%d, len=%u, *payload_offset=%d, *payload_size=%d src=%lx dst=%lx *rule=%p",
//                    (void *)packet, packet_size, *payload_offset, *payload_size, (__u32)src, (__u32)dst, (void *)rule));

//     ip = (ip_header *)packet;

//     if ((ip == NULL) || (ipsec_ntohs(ip->len) > packet_size))
//     {
//         IPSEC_LOG_DBG("ipsec_output", IPSEC_STATUS_NOT_IMPLEMENTED, ("bad packet ip=%p, ip->len=%d (must not be >%d bytes)", (void *)ip, ipsec_ntohs(ip->len), packet_size));

//         IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_output", ("return = %d", IPSEC_STATUS_BAD_PACKET));
//         return IPSEC_STATUS_BAD_PACKET;
//     }

//     if ((rule == NULL) || (rule->sa == NULL))
//     {
//         /** @todo invoke IKE to generate a proper SA for this SPD entry */
//         IPSEC_LOG_DBG("ipsec_output", IPSEC_STATUS_NOT_IMPLEMENTED, ("unable to generate dynamically an SA (IKE not implemented)"));

//         IPSEC_LOG_AUD("ipsec_output", IPSEC_STATUS_NO_SA_FOUND, ("no SA or SPD defined"));
//         IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_output", ("return = %d", IPSEC_STATUS_NO_SA_FOUND));
//         return IPSEC_STATUS_NO_SA_FOUND;
//     }

//     switch (rule->sa->protocol)
//     {
//     case IPSEC_PROTO_AH:
//         IPSEC_LOG_MSG("ipsec_output", ("have to encapsulate an AH packet"));
//         ret_val = ipsec_ah_encapsulate((ip_header *)packet, payload_offset, payload_size, rule->sa, src, dst);

//         if (ret_val != IPSEC_STATUS_SUCCESS)
//         {
//             IPSEC_LOG_ERR("ipsec_output", ret_val, ("ipsec_ah_encapsulate() failed"));
//         }
//         break;

//     case IPSEC_PROTO_ESP:
//         IPSEC_LOG_MSG("ipsec_output", ("have to encapsulate an ESP packet"));
//         ret_val = ipsec_esp_encapsulate((ip_header *)packet, payload_offset, payload_size, rule->sa, src, dst);

//         if (ret_val != IPSEC_STATUS_SUCCESS)
//         {
//             IPSEC_LOG_ERR("ipsec_output", ret_val, ("ipsec_esp_encapsulate() failed"));
//         }
//         break;

//     default:
//         ret_val = IPSEC_STATUS_BAD_PROTOCOL;
//         IPSEC_LOG_ERR("ipsec_output", ret_val, ("unsupported protocol '%d' in rule->sa->protocol", rule->sa->protocol));
//     }

//     IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_output", ("ret_val=%d", ret_val));
//     return ret_val;
// }
