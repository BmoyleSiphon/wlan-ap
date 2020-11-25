/* SPDX-License-Identifier: BSD-3-Clause */

#define _GNU_SOURCE
#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <net/if.h>

#include <sys/types.h>

#include <ev.h>

#include <syslog.h>
#include <unl.h>

#include "sm.h"
#include "ubus_collector.h"

#define MODULE_ID LOG_MODULE_ID_MAIN

/* global list populated by ubus_collector */
extern dpp_event_report_data_t g_report_data;
// dpp_event_report_data_t g_report_data;

/* new part */
typedef struct {
	bool initialized;

	/* Internal structure used to lower layer radio selection */
	radio_entry_t *radio_cfg;

	/* Internal structure used to lower layer radio selection */
	ev_timer report_timer;

	/* Structure containing cloud request timer params */
	sm_stats_request_t request;

	/* Structure pointing to upper layer events storage */
	dpp_event_report_data_t report;

	/* event list (only one for now) */
	ds_dlist_t record_list;

	/* Reporting start timestamp used for reporting timestamp calculation */
	uint64_t report_ts;
} sm_events_ctx_t;

/* Common place holder for all events stat report contexts */
sm_events_ctx_t g_sm_events_ctx;

/******************************************************************************
 *  PROTECTED definitions
 *****************************************************************************/
static bool dpp_events_report_timer_set(ev_timer *timer, bool enable)
{
	if (enable) {
		ev_timer_again(EV_DEFAULT, timer);
	} else {
		ev_timer_stop(EV_DEFAULT, timer);
	}

	return true;
}

static bool dpp_events_report_timer_restart(ev_timer *timer)
{
	sm_events_ctx_t *events_ctx = (sm_events_ctx_t *)timer->data;
	sm_stats_request_t *request_ctx = &events_ctx->request;

	if (request_ctx->reporting_count) {
		request_ctx->reporting_count--;

		LOG(DEBUG, "Updated events reporting count=%d",
		    request_ctx->reporting_count);

		/* If reporting_count becomes zero, then stop reporting */
		if (0 == request_ctx->reporting_count) {
			dpp_events_report_timer_set(timer, false);

			LOG(DEBUG, "Stopped events reporting (count expired)");
			return true;
		}
	}

	return true;
}

// static void dummy_data_events() {
	// ds_dlist_init(&g_report_data.list, dpp_event_record_t, node);

	// dpp_event_record_t *record = NULL;
	// record = calloc(1, sizeof(dpp_event_record_t));

	// ds_dlist_init(&record->dhcp_ack_event, dpp_event_record_dhcp_ack_t, node);

	// dpp_event_record_dhcp_ack_t *dhcp_ack_dummy = NULL;
	// dhcp_ack_dummy = dpp_event_dhcp_ack_record_alloc();
	// dhcp_ack_dummy->x_id = 2294967295;
	// dhcp_ack_dummy->vlan_id = 3294967295;
	// static const uint8_t ip_initializer[] = {192, 168, 0, 99};
	// memcpy(dhcp_ack_dummy->dhcp_server_ip, ip_initializer, 16);
	// memcpy(dhcp_ack_dummy->client_ip, ip_initializer, 16);
	// memcpy(dhcp_ack_dummy->relay_ip, ip_initializer, 16);
	// strcpy(dhcp_ack_dummy->device_mac_address, "02:42:09:06:cd:80");
	// memcpy(dhcp_ack_dummy->subnet_mask, ip_initializer, 16);
	// memcpy(dhcp_ack_dummy->primary_dns, ip_initializer, 16);
	// memcpy(dhcp_ack_dummy->secondary_dns, ip_initializer, 16);
	// dhcp_ack_dummy->lease_time = 94967295;
	// dhcp_ack_dummy->renewal_time = 494967295;
	// dhcp_ack_dummy->rebinding_time = 429496795;
	// dhcp_ack_dummy->time_offset = 294967295;
	// memcpy(dhcp_ack_dummy->gateway_ip, ip_initializer, 16);

	// ds_dlist_insert_tail(&record->dhcp_ack_event, dhcp_ack_dummy);

	// ds_dlist_insert_tail(&g_report_data.list, record);
// }

static void sm_events_report(EV_P_ ev_timer *w, int revents)
{
	sm_events_ctx_t *events_ctx = (sm_events_ctx_t *)w->data;
	dpp_event_report_data_t *report_ctx = &events_ctx->report;
	ev_timer *report_timer = &events_ctx->report_timer;

	dpp_events_report_timer_restart(report_timer);

	// LOG(INFO, "lkudra, calling dummy_data_events");
	// dummy_data_events();
	// LOG(INFO, "lkudra, dummy data finished");

	memcpy(report_ctx, &g_report_data, sizeof(dpp_event_report_data_t));

	while (!ds_dlist_is_empty(&g_report_data.list)) {
		ds_dlist_remove_head(&g_report_data.list);
	}

	LOG(INFO, "Sending events report...");
	if (!ds_dlist_is_empty(&report_ctx->list)) {
		dpp_put_events(report_ctx);
	}
}

/******************************************************************************
 *  PUBLIC API definitions
 *****************************************************************************/
bool sm_events_report_request(radio_entry_t *radio_cfg,
			      sm_stats_request_t *request)
{
	sm_events_ctx_t *events_ctx = &g_sm_events_ctx;
	sm_stats_request_t *request_ctx = &events_ctx->request;
	dpp_event_report_data_t *report_ctx = &events_ctx->report;
	ev_timer *report_timer = &events_ctx->report_timer;

	// save radio cfg
	events_ctx->radio_cfg = radio_cfg;

	if (NULL == request) {
		LOG(ERR, "Initializing events reporting "
			 "(Invalid request config)");
		return false;
	}

	/* Initialize global stats only once */
	if (!events_ctx->initialized) {
		memset(request_ctx, 0, sizeof(*request_ctx));
		memset(report_ctx, 0, sizeof(*report_ctx));

		LOG(INFO, "Initializing events reporting");

		/* Initialize report list */
		ds_dlist_init(&report_ctx->list, dpp_event_record_t, node);

		/* Initialize event list */
		ds_dlist_init(&events_ctx->record_list, dpp_event_record_t,
			      node);

		/* Initialize event lib timers and pass the global
			internal cache
		 */
		ev_init(report_timer, sm_events_report);
		report_timer->data = events_ctx;

		events_ctx->initialized = true;
	}

	/* Store and compare every request parameter ...
	memcpy would be easier but we want some debug info
	*/
	REQUEST_VAL_UPDATE("event", reporting_count, "%d");
	REQUEST_VAL_UPDATE("event", reporting_interval, "%d");
	REQUEST_VAL_UPDATE("event", reporting_timestamp, "%" PRIu64 "");

	/* Restart timers with new parameters */
	dpp_events_report_timer_set(report_timer, false);

	if (request_ctx->reporting_interval) {
		events_ctx->report_ts = get_timestamp();
		report_timer->repeat = request_ctx->reporting_interval;
		dpp_events_report_timer_set(report_timer, true);

		LOG(INFO, "Started events reporting");
	} else {
		LOG(INFO, "Stopped events reporting");
		memset(request_ctx, 0, sizeof(*request_ctx));
	}

	return true;
}
