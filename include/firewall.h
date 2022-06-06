

#ifndef __FIREWALL_H__
#define __FIREWALL_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "types.h"
#include "util.h"
#include "rules.h"

#include "debug.h"

int fw_input(unsigned char *, int, int *, int *, db_set_netif *);
// int fw_output(unsigned char *, int, int *, int *, __u32, __u32, void *);

#endif