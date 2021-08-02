
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#include <stdio.h>
#include <unistd.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_epoll_module.c"

#include "../ngx_mod_status.h"

static ngx_mds_main_ctx_t *ngx_mds_main_ctx = 0;

static ngx_str_t mds_epoll_name = ngx_string("mds_epoll");

static ngx_int_t ngx_mds_epoll_init(ngx_cycle_t *cycle, ngx_msec_t timer);

static ngx_int_t ngx_mds_epoll_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags);
static ngx_int_t ngx_mds_epoll_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags);
static ngx_int_t ngx_mds_epoll_add_connection(ngx_connection_t *c);
static ngx_int_t ngx_mds_epoll_del_connection(ngx_connection_t *c, ngx_uint_t flags);

static ngx_event_module_t  ngx_mds_epoll_module_ctx = {
	&mds_epoll_name,
	ngx_epoll_create_conf,               /* create configuration */
	ngx_epoll_init_conf,                 /* init configuration */

	{
		ngx_mds_epoll_add_event,             /* add an event */
		ngx_mds_epoll_del_event,             /* delete an event */
		ngx_epoll_add_event,             /* enable an event */
		ngx_epoll_del_event,             /* disable an event */
		ngx_mds_epoll_add_connection,        /* add an connection */
		ngx_mds_epoll_del_connection,        /* delete an connection */
#if (NGX_HAVE_EVENTFD)
		ngx_epoll_notify,                /* trigger a notify */
#else
		NULL,                            /* trigger a notify */
#endif
		ngx_epoll_process_events,        /* process the events */
		ngx_mds_epoll_init,                  /* init the events */
		ngx_epoll_done,                  /* done the events */
	}
};

ngx_module_t  ngx_mds_epoll = {
	NGX_MODULE_V1,
	&ngx_mds_epoll_module_ctx,               /* module context */
	ngx_epoll_commands,                  /* module directives */
	NGX_EVENT_MODULE,                    /* module type */
	NULL,                                /* init master */
	NULL,                                /* init module */
	NULL,                                /* init process */
	NULL,                                /* init thread */
	NULL,                                /* exit thread */
	NULL,                                /* exit process */
	NULL,                                /* exit master */
	NGX_MODULE_V1_PADDING
};

static void
ngx_mds_get_mod_status_module(ngx_cycle_t *cycle) {
	ngx_module_t *module;

	int i;
	for(i = 0; cycle->modules[i]; i++) {
		module = cycle->modules[i];

		if(ngx_strcmp(module->name, "ngx_mod_status") == 0) {
			ngx_mds_main_ctx = ngx_http_cycle_get_module_main_conf(cycle, (*module));

			return;
		}

	}
}

static ngx_int_t
ngx_mds_epoll_init(ngx_cycle_t *cycle, ngx_msec_t timer) {
	// +
	ngx_mds_get_mod_status_module(cycle);

	ngx_int_t ret = ngx_epoll_init(cycle, timer);

	// + overide epoll actions
	ngx_event_actions = ngx_mds_epoll_module_ctx.actions;

	return ret;
}

static ngx_int_t
ngx_mds_epoll_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags) {
	//return ngx_epoll_add_event(ev, event, flags);

	if(ngx_mds_main_ctx) {
		ngx_connection_t    *c;

		c = ev->data;

		int bit_pos = ((ngx_connection_t*)c)-((ngx_connection_t*)ngx_cycle->connections);

		ngx_mds_main_ctx->bmp_acc[BMP_POS(bit_pos)] |= BMP_SET(bit_pos);/**/
	}

	return ngx_epoll_add_event(ev, event, flags);
}

static ngx_int_t
ngx_mds_epoll_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags) {
	//return ngx_epoll_del_event(ev, event, flags);

	if(ngx_mds_main_ctx) {
		ngx_connection_t    *c;

		c = ev->data;

		int bit_pos = ((ngx_connection_t*)c)-((ngx_connection_t*)ngx_cycle->connections);

		ngx_mds_main_ctx->bmp_acc[BMP_POS(bit_pos)] &= BMP_CLR(bit_pos);/**/
	}

	return ngx_epoll_del_event(ev, event, flags);
}

static ngx_int_t
ngx_mds_epoll_add_connection(ngx_connection_t *c) {
	return ngx_epoll_add_connection(c);

	/*if(ngx_mds_main_ctx) {
		int bit_pos = ((ngx_connection_t*)c)-((ngx_connection_t*)ngx_cycle->connections);

		ngx_mds_main_ctx->bmp_acc[BMP_POS(bit_pos)] |= BMP_SET(bit_pos);
	}

	return ngx_epoll_add_connection(c);*/
}

static ngx_int_t
ngx_mds_epoll_del_connection(ngx_connection_t *c, ngx_uint_t flags) {
	return ngx_epoll_del_connection(c, flags);

	/*if(ngx_mds_main_ctx) {
		int bit_pos = ((ngx_connection_t*)c)-((ngx_connection_t*)ngx_cycle->connections);

		ngx_mds_main_ctx->bmp_acc[BMP_POS(bit_pos)] &= BMP_CLR(bit_pos);
	}

	return ngx_epoll_del_connection(c, flags);*/
}



