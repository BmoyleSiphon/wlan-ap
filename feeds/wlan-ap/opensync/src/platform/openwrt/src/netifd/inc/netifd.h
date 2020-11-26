/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef __NETIFD_H_
#define __NETIFD_H_

#include "os.h"
#include "util.h"
#include "ovsdb.h"
#include "ovsdb_update.h"
#include "ovsdb_sync.h"
#include "ovsdb_table.h"
#include "ovsdb_cache.h"
#include "schema.h"
#include "log.h"
#include "ds.h"
#include "target.h"

#include <linux/if.h>
#include <libubox/blobmsg.h>
#include "utils.h"

#include <libubox/avl.h>
#include <libubus.h>

/*
 * ===========================================================================
 *  DHCP events on UBUS
 * ===========================================================================
 */

struct dhcp_ack_event {
	uint32_t x_id;
	uint32_t vlan_id;
	uint8_t dhcp_server_ip[16];
	uint8_t client_ip[16];
	uint8_t relay_ip[16];
	char device_mac_address[20];
	uint8_t subnet_mask[16];
	uint8_t primary_dns[16];
	uint8_t secondary_dns[16];
	uint32_t lease_time;
	uint32_t renewal_time;
	uint32_t rebinding_time;
	uint32_t time_offset;
	uint8_t gateway_ip[16];
};

struct dhcp_nak_event {
	uint32_t x_id;
	uint32_t vlan_id;
	uint8_t dhcp_server_ip[16];
	uint8_t client_ip[16];
	uint8_t relay_ip[16];
	char device_mac_address[20];
	bool from_internal;
};

struct dhcp_offer_event {
	uint32_t x_id;
	uint32_t vlan_id;
	uint8_t dhcp_server_ip[16];
	uint8_t client_ip[16];
	uint8_t relay_ip[16];
	char device_mac_address[20];
	bool from_internal;
};

struct dhcp_inform_event {
	uint32_t x_id;
	uint32_t vlan_id;
	uint8_t dhcp_server_ip[16];
	uint8_t client_ip[16];
	uint8_t relay_ip[16];
	char device_mac_address[20];
};

struct dhcp_decline_event {
	uint32_t x_id;
	uint32_t vlan_id;
	uint8_t dhcp_server_ip[16];
	uint8_t client_ip[16];
	uint8_t relay_ip[16];
	char device_mac_address[20];
};

struct dhcp_request_event {
	uint32_t x_id;
	uint32_t vlan_id;
	uint8_t dhcp_server_ip[16];
	uint8_t client_ip[16];
	uint8_t relay_ip[16];
	char device_mac_address[20];
	char hostname[253 + 1];
};

struct dhcp_discover_event {
	uint32_t x_id;
	uint32_t vlan_id;
	uint8_t dhcp_server_ip[16];
	uint8_t client_ip[16];
	uint8_t relay_ip[16];
	char device_mac_address[20];
	char hostname[253 + 1];
};

struct dhcp_event_record {
	int type;
	struct timespec ts;
	union {
		struct dhcp_ack_event ack;
		struct dhcp_nak_event nak;
		struct dhcp_offer_event offer;
		struct dhcp_inform_event inform;
		struct dhcp_decline_event decline;
		struct dhcp_request_event request;
		struct dhcp_discover_event discover;
	} u;
};

struct dhcp_event_avl_rec {
	struct dhcp_event_record *records;
	size_t rec_nr;
	struct avl_node avl;
};

#define SCHEMA_FIND_KEY(x, key)    __find_key(	 \
	(char *)x##_keys, sizeof(*(x ## _keys)), \
	(char *)x, sizeof(*(x)), x##_len, key)

static inline const char * __find_key(char *keyv, size_t keysz, char *datav, size_t datasz, int vlen, const char *key)
{
	int ii;

	for (ii = 0; ii < vlen; ii++) {
		if (strcmp(keyv, key) == 0)
			return datav;
		keyv += keysz;
		datav += datasz;
	}

	return NULL;
}

struct iface_info {
	char name[IFNAMSIZ];
	int vid;
};

extern int l3_device_split(char *l3_device, struct iface_info *info);

extern struct blob_buf b;
extern ovsdb_table_t table_Wifi_Inet_Config;
extern struct uci_context *uci;

extern void wifi_inet_config_init(void);
extern void wifi_inet_state_init(void);
extern void wifi_inet_state_set(struct blob_attr *msg);
extern void wifi_inet_master_set(struct blob_attr *msg);

extern int netifd_ubus_init(struct ev_loop *loop);
extern int netfid_ubus_handle_dhcp_event(struct dhcp_event_record);

extern void dhcp_add(char *net, const char *lease_time, const char *start, const char *limit);
extern void dhcp_del(char *net);
extern void dhcp_get_state(struct schema_Wifi_Inet_State *state);
extern void dhcp_get_config(struct schema_Wifi_Inet_Config *conf);
extern void dhcp_lease(const char *method, struct blob_attr *msg);

extern void firewall_add_zone(char *net, int nat);
extern void firewall_del_zone(char *net);
extern void firewall_get_state(struct schema_Wifi_Inet_State *state);
extern void firewall_get_config(struct schema_Wifi_Inet_Config *conf);

#endif
