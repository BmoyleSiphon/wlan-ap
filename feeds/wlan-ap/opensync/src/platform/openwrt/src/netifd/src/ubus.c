/* SPDX-License-Identifier: BSD-3-Clause */

#include <syslog.h>
#include "target.h"

#include "evsched.h"
#include "netifd.h"
#include "ubus.h"

static struct ubus_context *ubus;

static int netifd_ubus_notify(struct ubus_context *ctx, struct ubus_object *obj,
			     struct ubus_request_data *req, const char *method,
			     struct blob_attr *msg)
{
	char *str;

	str = blobmsg_format_json(msg, true);
	LOGN("ubus: Received ubus notify '%s': %s\n", method, str);
	free(str);

	LOG(INFO, "lkudra, method: %s", method);

	if (!strncmp(method, "dhcp.", 5)) {
		dhcp_lease(method, msg);
	} else if (!strncmp(method, "interface.", 10)) {
		wifi_inet_state_set(msg);
		wifi_inet_master_set(msg);
	}

	return 0;
}

static int
ubus_dhcp_ack_events_cb(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	return UBUS_STATUS_OK;
}

static int
ubus_dhcp_nak_events_cb(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	return UBUS_STATUS_OK;
}

static int
ubus_dhcp_offer_events_cb(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	return UBUS_STATUS_OK;
}

static int
ubus_dhcp_inform_events_cb(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	return UBUS_STATUS_OK;
}

static int
ubus_dhcp_decline_events_cb(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	return UBUS_STATUS_OK;
}

static int
ubus_dhcp_request_events_cb(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	return UBUS_STATUS_OK;
}

static int
ubus_dhcp_discover_events_cb(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	return UBUS_STATUS_OK;
}

static const struct ubus_method netifd_ubus_methods[] = {
        UBUS_METHOD_NOARG("get_dhcp_ack_events", ubus_dhcp_ack_events_cb),
        UBUS_METHOD_NOARG("get_dhcp_nak_events", ubus_dhcp_nak_events_cb),
        UBUS_METHOD_NOARG("get_dhcp_offer_events", ubus_dhcp_offer_events_cb),
        UBUS_METHOD_NOARG("get_dhcp_inform_events", ubus_dhcp_inform_events_cb),
        UBUS_METHOD_NOARG("get_dhcp_decline_events", ubus_dhcp_decline_events_cb),
        UBUS_METHOD_NOARG("get_dhcp_request_events", ubus_dhcp_request_events_cb),
        UBUS_METHOD_NOARG("get_dhcp_discover_events", ubus_dhcp_discover_events_cb),
};

static struct ubus_object_type netifd_ubus_object_type =
        UBUS_OBJECT_TYPE("osync-dhcp", netifd_ubus_methods);

static struct ubus_object netifd_ubus_object = {
        .name = "osync-dhcp",
        .type = &netifd_ubus_object_type,
        .methods = netifd_ubus_methods,
        .n_methods = ARRAY_SIZE(netifd_ubus_methods),
};

static void netifd_ubus_connect(struct ubus_context *ctx)
{
	ubus = ctx;
	ubus_add_object(ubus, &netifd_ubus_object);
}

static struct ubus_instance ubus_instance = {
	.connect = netifd_ubus_connect,
	.notify = netifd_ubus_notify,
	.list = {
			{
				.path = "network.interface.",
				.wildcard = 1,
			},
			{
				.path = "dnsmasq",
			},
		},
	.len = 2,
};

int netifd_ubus_init(struct ev_loop *loop)
{
	return ubus_init(&ubus_instance, loop);
}
