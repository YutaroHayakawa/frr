/*
 * BPF plugin for the FRR zebra dataplane.
 *
 * Copyright (c) 2022 Yutaro Hayakawa
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "config.h"
#include "lib/zebra.h"
#include "lib/libfrr.h"
#include "linux/seg6_local.h"
#include "nexthop.h"
#include "zebra/zebra_dplane.h"
#include "zebra/debug.h"
#include "zlog.h"

#include <asm-generic/errno-base.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <string.h>

extern struct zebra_privs_t zserv_privs;
static struct zebra_dplane_provider *prov_p;

static int seg6local_map_fd = -1;

struct seg6local_key {
	struct bpf_lpm_trie_key base;
	struct in6_addr prefix;
	uint8_t _pad[12];
} __attribute__((packed));

struct seg6local_val {
	uint32_t action;
	union {
		uint32_t vrftable;
	} attr;
} __attribute__((packed));

#define BPFFS_PATH "/sys/fs/bpf"
#define SEG6LOCAL_MAP_MAX_ENTRIES 1024
#define SEG6LOCAL_MAP_NAME "zebra_seg6local_map"
#define SEG6LOCAL_MAP_PATH BPFFS_PATH "/" SEG6LOCAL_MAP_NAME

static void zd_bpf_route_update(struct zebra_dplane_ctx *ctx)
{
	int error;

	const struct prefix *prefix = dplane_ctx_get_dest(ctx);
	if (prefix->family != AF_INET6)
		return;

	struct nexthop *nexthop = dplane_ctx_get_ng(ctx)->nexthop;
	if (nexthop == NULL)
		return;

	struct nexthop_srv6 *nh_srv6 = nexthop->nh_srv6;
	if (nh_srv6 == NULL)
		return;

	if (nh_srv6->seg6local_action !=
			ZEBRA_SEG6_LOCAL_ACTION_END_DT4)
		return;

	zlog_debug("%s: got an End.DT4 route (sid: %pFX, vrftable: %u), skipping kernel",
			__func__, prefix, nh_srv6->seg6local_ctx.table);

	struct seg6local_key k = {
		.base = {
			.prefixlen = prefix->prefixlen + 8 * sizeof(k._pad),
		},
		.prefix = prefix->u.prefix6,
	};

	frr_with_privs(&zserv_privs) {
		switch (dplane_ctx_get_op(ctx)) {
		case DPLANE_OP_ROUTE_UPDATE:
		case DPLANE_OP_ROUTE_INSTALL:
			struct seg6local_val v = {
				.action = SEG6_LOCAL_ACTION_END_DT4,
				.attr = {
					.vrftable = nh_srv6->seg6local_ctx.table,
				},
			};

			error = bpf_map_update_elem(seg6local_map_fd, &k, &v, 0);
			if (error == -1)
				zlog_warn("Failed to update seg6local map: %s", strerror(errno));

			break;
		case DPLANE_OP_ROUTE_DELETE:
			error = bpf_map_delete_elem(seg6local_map_fd, &k);
			if (error == -1)
				zlog_warn("Failed to delete seg6local map: %s", strerror(errno));

			break;
		default:
			break;
		}
	}

	dplane_ctx_set_skip_kernel(ctx);
}

static void zd_bpf_nh_update(struct zebra_dplane_ctx *ctx)
{
	const struct nexthop_group *ng = dplane_ctx_get_ng(ctx);

	if (ng == NULL || ng->nexthop == NULL) {
		return;
	}

	if (ng->nexthop->nh_srv6 == NULL) {
		return;
	}

	zlog_debug("%s: %pNH", __func__, ng->nexthop);
}

static void zd_bpf_process_update(struct zebra_dplane_provider *prov, struct zebra_dplane_ctx *ctx)
{
	switch (dplane_ctx_get_op(ctx)) {
	case DPLANE_OP_ROUTE_INSTALL:
	case DPLANE_OP_ROUTE_UPDATE:
	case DPLANE_OP_ROUTE_DELETE:
		zd_bpf_route_update(ctx);
		break;
	case DPLANE_OP_NH_INSTALL:
	case DPLANE_OP_NH_UPDATE:
	case DPLANE_OP_NH_DELETE:
		zd_bpf_nh_update(ctx);
		break;
	default:
		break;
	}
}

static int bpf_start(struct zebra_dplane_provider *prov)
{
	int error, fd;

	struct bpf_map_create_opts opts = {
		.sz = sizeof(opts),
		.map_flags = BPF_F_NO_PREALLOC,
	};

	frr_with_privs(&zserv_privs) {
		fd = bpf_obj_get(SEG6LOCAL_MAP_PATH);
		if (fd > 0) {
			zlog_info("Found an existing map on %s. Using it.\n", SEG6LOCAL_MAP_PATH);
		} else if (fd < 0 && errno  == ENOENT) {
			zlog_info("Couldn't find an existing map on %s. Creating a new one.\n", SEG6LOCAL_MAP_PATH);

			fd = bpf_map_create(BPF_MAP_TYPE_LPM_TRIE, SEG6LOCAL_MAP_NAME,
						sizeof(struct seg6local_key), sizeof(struct seg6local_val),
						SEG6LOCAL_MAP_MAX_ENTRIES, &opts);
			if (fd == -1)
				zlog_warn("Failed to setup seg6local map: %s", strerror(errno));

			error = bpf_obj_pin(fd, SEG6LOCAL_MAP_PATH);
			if (error == -1) {
				close(fd);
				zlog_warn("Failed to pin seg6local map: %s", strerror(errno));
			}
		} else {
			zlog_warn("Got an error while finding an existing map on %s: %s\n", SEG6LOCAL_MAP_PATH, strerror(errno));
		}
	}

	seg6local_map_fd = fd;

	return 0;
}

static int bpf_process(struct zebra_dplane_provider *prov)
{
	int counter, limit;
	struct zebra_dplane_ctx *ctx;

	zlog_debug("%s called", __func__);

	limit = dplane_provider_get_work_limit(prov_p);

	/* Respect the configured limit on the amount of work to do in
	 * any one call.
	 */
	for (counter = 0; counter < limit; counter++) {
		ctx = dplane_provider_dequeue_in_ctx(prov_p);
		if (!ctx)
			break;

		zd_bpf_process_update(prov, ctx);

		/* Just set 'success' status and return to the dataplane */
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_SUCCESS);
		dplane_provider_enqueue_out_ctx(prov_p, ctx);
	}

	return 0;
}

static int bpf_fini(struct zebra_dplane_provider *prov, bool early)
{
	if (seg6local_map_fd != -1)
		close(seg6local_map_fd);

	return 0;
}

static int init_bpf_plugin(struct thread_master *tm)
{
	return dplane_provider_register("BPF", DPLANE_PRIO_PRE_KERNEL,
					DPLANE_PROV_FLAGS_DEFAULT,
					bpf_start,
					bpf_process,
					bpf_fini,
					NULL,
					&prov_p);
}

static int module_init(void)
{
	hook_register(frr_late_init, init_bpf_plugin);
	return 0;
}

FRR_MODULE_SETUP(
	.name = "dplane_bpf",
	.version = "0.0.1",
	.description = "BPF Dataplane",
	.init = module_init,
);
