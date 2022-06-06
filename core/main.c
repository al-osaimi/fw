

#include "firewall.h"
#include "test.h"

extern rule_entry outbound_spd_config[]; /**< inbound SAD configuration data  */
extern rule_entry inbound_spd_config[];  /**< inbound SPD configuration data  */

extern db_set_netif db_sets[];
db_set_netif *databases;

fw_status init()
{
    struct ipsecdev_stats *ipsecdev_stats;

    IPSEC_LOG_TRC(IPSEC_TRACE_ENTER,
                  "ipsecdev_init", ("dd"));

    /**@todo this should be somewhere else */
    /* initialize the db_sets structure */
    memset(db_sets, 0, FW_NR_NETIFS * sizeof(db_set_netif));

    databases = fw_rule_load_dbs(inbound_spd_config, outbound_spd_config);

    if (databases == NULL)
    {
        IPSEC_LOG_ERR("init", -1, ("not able to load SPD and SA configuration for ipsec device"));
    }

    IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "init", ("retcode = %d", IPSEC_STATUS_SUCCESS));
    return IPSEC_STATUS_SUCCESS;
}

int main(void)
{

    printf("main\n");
    init();
    fw_rule_print(databases);
    return 0;
}
