
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#include <stdio.h>
#include <unistd.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "../ngx_mod_status.h"

static ngx_int_t ngx_mds_handler(ngx_http_request_t *r);
static ngx_int_t ngx_mds_variable(ngx_http_request_t *r,
								  ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_mds_add_variables(ngx_conf_t *cf);
static char *ngx_mds_set_commands(ngx_conf_t *cf, ngx_command_t *cmd,
								  void *conf);
static void *ngx_mds_create_main_conf(ngx_conf_t *cf);
static char *ngx_mds_init_main_conf(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_mds_init_proc(ngx_cycle_t* cycle);
static void *ngx_mds_create_loc_conf(ngx_conf_t *cf);
static char *ngx_mds_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_mds_postconf(ngx_conf_t *cf);
static ngx_int_t ngx_mds_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_mds_phase_handler(ngx_http_request_t *r, int phase_idx, int do_lock, ngx_connection_t *c, int ignore_rec);
static void ngx_mds_reset_buf_indices(int reset_acc, int reset_log, int proc_idx);
static ngx_int_t get_buf(int proc_idx, char **buf, ngx_mds_sync_proc_t **sync_proc, ngx_mds_main_ctx_t *ngx_mds_main_ctx, int phase_idx, int from_start);

//static ngx_shmtx_t ngx_mds_mutex;

int
ngx_mds_shmtx_trylock(ngx_shmtx_t *mtx) {
	ngx_uint_t         i, n;

	for(;;) {

		if(*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid)) {
			return 1;
		}

		if(ngx_ncpu > 1) {

			for(n = 1; n < mtx->spin; n <<= 1) {

				for(i = 0; i < n; i++) {
					ngx_cpu_pause();
				}

				if(*mtx->lock == 0
						&& ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid)) {
					return 1;
				}
			}
		}

		//ngx_sched_yield();
		return 0;
	}
}

static ngx_int_t
bound_val(ngx_int_t val, ngx_int_t min, ngx_int_t max) {
	if(val<min) {
		return min;
	} else if(val>max) {
		return max;
	}

	return val;
}

static ngx_int_t
is_outbounded(ngx_int_t val, ngx_int_t min, ngx_int_t max) {
	return val<=min || val>=max;
}

#define PHASE_CNT 2
#define PHASE_ACC_IDX 0
#define PHASE_LOG_IDX 1

#define CMD_MSG_HNDL "ngx_mds"
#define CMD_MSG_SIZE "ngx_mds_msg_size"
#define CMD_MSG_CNT "ngx_mds_msg_count"

#define SHM_NAME "__ngx_mds_shm__"
#define SHM_LCK_FL "log/ngx_mod_status.lock"

#define DFT_MSG_SIZE 500
#define DFT_MSG_CNT 50

#define MAX_REC_MS 10000
#define MIN_REC_MS 100
#define DFT_REC_MS 1000

#define DFT_TMR_MS 500

#define ID_SZ (sizeof(ngx_connection_t*)*2)
#define PH_SZ 1
#define PORT_SZ 5

static char* stat_json = "[\"%lx\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]";
static char* stat_json_c = "[\"%lx\",\"%s\"]";

static ngx_command_t  ngx_mds_commands[] = {

	{
		ngx_string(CMD_MSG_HNDL),
		NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
		ngx_mds_set_commands,
		0,
		0,
		NULL
	},

	{
		ngx_string(CMD_MSG_SIZE),
		NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_mds_set_commands,
		0,
		0,
		NULL
	},

	{
		ngx_string(CMD_MSG_CNT),
		NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_mds_set_commands,
		0,
		0,
		NULL
	},

	ngx_null_command
};


static ngx_http_module_t  ngx_mds_module_ctx = {
	ngx_mds_add_variables,    /* preconfiguration */
	ngx_mds_postconf,                                  /* postconfiguration */

	ngx_mds_create_main_conf,                                  /* create main configuration */
	ngx_mds_init_main_conf,                                  /* init main configuration */

	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */

	NULL,                                  /* create location configuration */
	NULL                                   /* merge location configuration */
};

static ngx_int_t ngx_mds_init_module(ngx_cycle_t* cycle);

ngx_module_t  ngx_mod_status = {
	NGX_MODULE_V1,
	&ngx_mds_module_ctx,      /* module context */
	ngx_mds_commands,              /* module directives */
	NGX_HTTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	ngx_mds_init_module,              /* init module */
	ngx_mds_init_proc,                                  /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};

static ngx_http_variable_t  ngx_mds_vars[] = {

	{
		ngx_string("connections_active2"), NULL, ngx_mds_variable,
		0, NGX_HTTP_VAR_NOCACHEABLE, 0
	},

	{
		ngx_string("connections_reading2"), NULL, ngx_mds_variable,
		1, NGX_HTTP_VAR_NOCACHEABLE, 0
	},

	{
		ngx_string("connections_writing2"), NULL, ngx_mds_variable,
		2, NGX_HTTP_VAR_NOCACHEABLE, 0
	},

	{
		ngx_string("connections_waiting2"), NULL, ngx_mds_variable,
		3, NGX_HTTP_VAR_NOCACHEABLE, 0
	},

	ngx_http_null_variable
};

static ngx_int_t ngx_mds_init_module(ngx_cycle_t* cycle) {
	ngx_mds_main_ctx_t *ngx_mds_main_ctx = ngx_http_cycle_get_module_main_conf(cycle, ngx_mod_status);

	if(ngx_mds_main_ctx == NULL) {
		return NGX_ERROR;
	}

	ngx_mds_sync_t *sync_zone = (ngx_mds_sync_t *)(((char *)ngx_mds_main_ctx->shm_zone->shm.addr)+sizeof(ngx_slab_pool_t));

	sync_zone->record_msec = DFT_REC_MS;
	sync_zone->record_msec_start = 0;
	sync_zone->record_msec_elapsed = 0;
	sync_zone->is_recording = 0;
	sync_zone->expl = 0;

	//ngx_accept_mutex_held = 1;

	/*if (ngx_shmtx_create(&ngx_mds_mutex, (ngx_shmtx_sh_t *) &sync_zone->shm_mutex, SHM_LCK_FL) != NGX_OK) {
	    return NGX_ERROR;
	}*/

	return NGX_OK;
}

static int
ngx_mds_con_freed(ngx_connection_t *c) {
	ngx_connection_t *c_free = ngx_cycle->free_connections;

	while(c_free!=NULL) {
		if(c_free==c)
			return 1;

		c_free = c_free->data;
	}

	return 0;
}

static void
ngx_mds_init_proc_ev_con_handler(ngx_event_t *ev) {
	int n;

	if(ngx_exiting || ev == NULL)
		return;

	ngx_mds_main_ctx_t *ngx_mds_main_ctx = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_mod_status);
	ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)ngx_mds_main_ctx->shm_zone->shm.addr;
	ngx_mds_sync_t *sync_zone = (ngx_mds_sync_t *)(((char *)ngx_mds_main_ctx->shm_zone->shm.addr)+sizeof(ngx_slab_pool_t));

	ngx_shmtx_lock(&shpool->mutex);

	if(!sync_zone->is_recording) {
		ngx_shmtx_unlock(&shpool->mutex);
		ngx_add_timer(ev, DFT_TMR_MS);

		return;
	}

	ngx_mds_reset_buf_indices(0, 1, ngx_process_slot);

	for(n = 0; n < ngx_cycle->connection_n; n++) {
		ngx_connection_t *c;
		ngx_http_request_t *r = 0;
		ngx_http_log_ctx_t *ctx;

		c = (ngx_connection_t *)&ngx_cycle->connections[n];

		int pass = 0;
		if(sync_zone->expl && c && c->log && c->log->data && ((c->read->active && !c->read->ready) || (c->write->active && !c->write->ready)) && c->fd != -1) {
			pass = 1;
		} else if(!sync_zone->expl && c) {
			pass = 1;
		}

		if(pass) {
			int bit_pos = ((ngx_connection_t*)c)-((ngx_connection_t*)ngx_cycle->connections);

			if(!sync_zone->expl && !BMP_GET(ngx_mds_main_ctx->bmp_acc, bit_pos))
				continue;

			ctx = (c->log && c->log->data) ? c->log->data : 0;
			r = ctx ? ctx->request : 0;

			if(!r || r->connection!=c)
				continue;

			ngx_mds_phase_handler(r, PHASE_LOG_IDX, 0, 0, 1);

		}

	}

	ngx_shmtx_unlock(&shpool->mutex);

	ngx_add_timer(ev, DFT_TMR_MS);
}

static ngx_int_t
ngx_mds_init_proc(ngx_cycle_t* cycle) {
	ngx_event_t *ev;
	ngx_mds_sync_proc_t *sync_proc;
	char *buf_acc;

	ngx_mds_main_ctx_t *ngx_mds_main_ctx = ngx_http_cycle_get_module_main_conf(cycle, ngx_mod_status);

	ngx_core_conf_t *ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx, ngx_core_module);

	if(ngx_mds_main_ctx == NULL) {
		return NGX_ERROR;
	}

	int ret = get_buf(ngx_process_slot, &buf_acc, &sync_proc, ngx_mds_main_ctx, PHASE_ACC_IDX, 1);

	sync_proc->pid = ngx_getpid();

	char* buf;

	buf = ngx_alloc(NGX_SOCKADDR_STRLEN, cycle->log);
	if(buf==NULL)
		return NGX_ERROR;
	ngx_mds_main_ctx->addr_text.data = buf;
	memset(ngx_mds_main_ctx->addr_text.data, 0, NGX_SOCKADDR_STRLEN);

	ev = &ngx_mds_main_ctx->ev_con;
	ev->handler = ngx_mds_init_proc_ev_con_handler;
	ev->log = ngx_cycle->log;
	ev->data = ngx_mds_main_ctx;

	// experimental, probably should comment below
	ngx_add_timer(ev, DFT_TMR_MS);

	return NGX_OK;
}

static ngx_int_t
get_buf(int proc_idx, char **buf, ngx_mds_sync_proc_t **sync_proc, ngx_mds_main_ctx_t *ngx_mds_main_ctx, int phase_idx, int from_start) {
	ngx_mds_sync_proc_t *_sync_proc = (ngx_mds_sync_proc_t *)(((char *) ngx_mds_main_ctx->shm_zone->shm.addr)+
									  proc_idx*(sizeof(ngx_mds_sync_proc_t)+ngx_mds_main_ctx->msg_size*ngx_mds_main_ctx->msg_count*PHASE_CNT)+
									  sizeof(ngx_mds_sync_t)+sizeof(ngx_slab_pool_t));

	ngx_int_t phase_len = 0;

	if(!from_start) {
		if((phase_idx==PHASE_ACC_IDX && _sync_proc->phase_acc_idx>=ngx_mds_main_ctx->msg_count) ||
				(phase_idx==PHASE_LOG_IDX && _sync_proc->phase_log_idx>=ngx_mds_main_ctx->msg_count)) {
			//ngx_mds_reset_buf_indices(1, 0);
			return NGX_ERROR;
		}

		phase_len = phase_idx==PHASE_ACC_IDX ? _sync_proc->phase_acc_len : _sync_proc->phase_log_len;
	}

	char* _buf = (char *)(((char *)_sync_proc)+ngx_mds_main_ctx->msg_size*ngx_mds_main_ctx->msg_count*phase_idx+sizeof(ngx_mds_sync_proc_t)+phase_len);

	*sync_proc = _sync_proc;
	*buf = _buf;

	return NGX_OK;
}

int add_ngx_buf(ngx_chain_t** cl, ngx_chain_t*** ll, ngx_buf_t* b, ngx_http_request_t* r) {
	*cl = ngx_alloc_chain_link(r->pool);
	if(*cl == NULL) {
		return 1;
	}

	(*cl)->buf = b;

	**ll = *cl;
	*ll = &(*cl)->next;

	**ll = NULL;

	return 0;
}

//
static char* str0 = "Total connections: %d\nUsed connections: %d \n\n";
static char* str1 = "Accepted connections: %d\nHandled connections: %d\nTotal requests: %d \n\n";
static char* str2 =
	"Reading: %d\nWriting: %d\nWaiting: %d\n\n\
 <span id=\"dot\" class=\"dot_green\"></span> <span id=\"is_recording\"></span>";
static char* str3 = "\nConnection state:\nR - reading the request header\nW - writing the response back to the client \nP - processing";

static char *html_head_start =
	"<html>\n\
	<head>\n\
		<title>nginx mod status</title>\n\
		<style>\n\
		.dot_green, .dot_red {\n\
			height: 1em;\n\
			width: 1em;\n\
			border: 1px solid #000000;\n\
			border-radius: 50%;\n\
			display: inline-block;\n\
		}\n\
		.dot_green {\n\
			background-color: green;\n\
		}\n\
		.dot_red {\n\
			background-color: red;\n\
		}\n\
		</style>\n\
		<script src=\"ngx_mod_status.js\"></script>\n\
		<script>\n\
			var stats_arr = [";

static char *html_head_end =
	"];\n\
			var record_msec = %d;\n\
			var record_msec_left = %d;\n\
			var expl = %d;\n\
		</script>\n\
	</head>";

static char *html_body_start =
	"\n\
	<body>\n\
		<pre>\n";

static char *html_body_end =
	"		<div id=\"stats\"></div>";

static char *html_footer =
	"\n\
		</pre>\n\
	</body>\n\
</html>";

static ngx_int_t
ngx_mds_send_header(ngx_http_request_t *r, char* content_type) {
	ngx_int_t rc;

	if(!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
		return NGX_HTTP_NOT_ALLOWED;
	}

	rc = ngx_http_discard_request_body(r);

	if(rc != NGX_OK) {
		return rc;
	}

	r->headers_out.content_type_len = strlen(content_type);
	r->headers_out.content_type.data = content_type;
	r->headers_out.content_type.len = r->headers_out.content_type_len;
	r->headers_out.content_type_lowcase = NULL;

	if(r->method == NGX_HTTP_HEAD) {
		r->headers_out.status = NGX_HTTP_OK;

		rc = ngx_http_send_header(r);

		if(rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
			return rc;
		}
	}

	return NGX_OK;
}

static void
ngx_mds_try_stop_rec(ngx_mds_sync_t *sync_zone, ngx_uint_t msec) {
	sync_zone->record_msec_elapsed = bound_val(msec-sync_zone->record_msec_start, 0, sync_zone->record_msec);

	if(is_outbounded(sync_zone->record_msec_elapsed+1, 0, sync_zone->record_msec))
		sync_zone->is_recording = 0;
}

static ngx_int_t
ngx_mds_stats_handler(ngx_http_request_t *r) {
	ngx_int_t rc;
	ngx_int_t msec_left;
	ngx_core_conf_t *ccf;

	ngx_atomic_int_t ap, hn, ac, rq, rd, wr, wa;

	ngx_buf_t *b;
	ngx_chain_t *chain;
	ngx_chain_t *cl, **ll;

	ap = *ngx_stat_accepted;
	hn = *ngx_stat_handled;
	ac = *ngx_stat_active;
	rq = *ngx_stat_requests;
	rd = *ngx_stat_reading;
	wr = *ngx_stat_writing;
	wa = *ngx_stat_waiting;

	ll = &chain;

	unsigned int n;
	ngx_cycle_t *cycle = (ngx_cycle_t *) ngx_cycle;

	int len_tot = 0;
	int len = 0;

	// html_head_start
	len = snprintf(0, 0, "%s", html_head_start);
	if(len<0)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	b = ngx_create_temp_buf(r->pool, len);
	if(b == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	b->last = ngx_sprintf(b->last, "%s", html_head_start);
	if(add_ngx_buf(&cl, &ll, b, r))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	len_tot += len;

	//
	ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx, ngx_core_module);

	ngx_mds_main_ctx_t *ngx_mds_main_ctx = ngx_http_get_module_main_conf(r, ngx_mod_status);
	ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)ngx_mds_main_ctx->shm_zone->shm.addr;
	ngx_mds_sync_t *sync_zone = (ngx_mds_sync_t *)(((char *)ngx_mds_main_ctx->shm_zone->shm.addr)+sizeof(ngx_slab_pool_t));

	int is_recording = 0;

	ngx_shmtx_lock(&shpool->mutex);
	//ngx_shmtx_trylock(&shpool->mutex);
	//if(ngx_shmtx_trylock(&shpool->mutex)) {
	//if(ngx_mds_shmtx_trylock(&shpool->mutex)) {

	ngx_int_t msec = ngx_current_msec;

	ngx_mds_try_stop_rec(sync_zone, msec);

	is_recording = sync_zone->is_recording;

	//if(!is_recording) {
	int i;
	for(i=0; i<ccf->worker_processes; i++) {
		ngx_mds_sync_proc_t *sync_proc;
		char *buf_acc, *buf_log;

		char* buf_obj = "{pid:%d,acc:[%s],log:[%s]},";
		if(i==ccf->worker_processes-1)
			buf_obj = "{pid:%d,acc:[%s],log:[%s]}";

		int len_acc = -1, len_log = -1;
		ngx_int_t ret;

		ret = get_buf(i, &buf_acc, &sync_proc, ngx_mds_main_ctx, PHASE_ACC_IDX, 1);
		len_acc = sync_proc->phase_acc_len;

		ret = get_buf(i, &buf_log, &sync_proc, ngx_mds_main_ctx, PHASE_LOG_IDX, 1);
		len_log = sync_proc->phase_log_len;

		//
		len = snprintf(0, 0, buf_obj, sync_proc->pid, buf_acc, buf_log);
		if(len<0)
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		b = ngx_create_temp_buf(r->pool, len);
		if(b == NULL)
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		b->last = ngx_sprintf(b->last, buf_obj, sync_proc->pid, buf_acc, buf_log);
		if(add_ngx_buf(&cl, &ll, b, r))
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		len_tot += len;
	}
	//}

	ngx_shmtx_unlock(&shpool->mutex);


	//}

	// html_head_end
	len = snprintf(0, 0, html_head_end, sync_zone->record_msec, sync_zone->record_msec-sync_zone->record_msec_elapsed, sync_zone->expl);
	if(len<0)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	b = ngx_create_temp_buf(r->pool, len);
	if(b == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	b->last = ngx_sprintf(b->last, html_head_end, sync_zone->record_msec, sync_zone->record_msec-sync_zone->record_msec_elapsed, sync_zone->expl);
	if(add_ngx_buf(&cl, &ll, b, r))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	len_tot += len;

	// html_body_start
	len = snprintf(0, 0, "%s", html_body_start);
	if(len<0)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	b = ngx_create_temp_buf(r->pool, len);
	if(b == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	b->last = ngx_sprintf(b->last, "%s", html_body_start);
	if(add_ngx_buf(&cl, &ll, b, r))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	len_tot += len;

	//
	len = snprintf(0, 0, str0, cycle->connection_n, cycle->connection_n-cycle->free_connection_n);
	if(len<0)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	b = ngx_create_temp_buf(r->pool, len);
	if(b == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	b->last = ngx_sprintf(b->last, str0, cycle->connection_n, cycle->connection_n-cycle->free_connection_n);
	if(add_ngx_buf(&cl, &ll, b, r))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	len_tot += len;

	//
	len = snprintf(0, 0, str1, ap, hn, rq);
	if(len<0)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	b = ngx_create_temp_buf(r->pool, len);
	if(b == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	b->last = ngx_sprintf(b->last, str1, ap, hn, rq);
	if(add_ngx_buf(&cl, &ll, b, r))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	len_tot += len;

	//
	len = snprintf(0, 0, str2, rd, wr, wa);
	if(len<0)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	b = ngx_create_temp_buf(r->pool, len);
	if(b == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	b->last = ngx_sprintf(b->last, str2, rd, wr, wa);
	if(add_ngx_buf(&cl, &ll, b, r))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	len_tot += len;

	// html_body_end
	len = snprintf(0, 0, "%s", html_body_end);
	if(len<0)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	b = ngx_create_temp_buf(r->pool, len);
	if(b == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	b->last = ngx_sprintf(b->last, "%s", html_body_end);
	if(add_ngx_buf(&cl, &ll, b, r))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	len_tot += len;

	//
	len = snprintf(0, 0, "%s", str3);
	if(len<0)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	b = ngx_create_temp_buf(r->pool, len);
	if(b == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	b->last = ngx_sprintf(b->last, "%s", str3);
	if(add_ngx_buf(&cl, &ll, b, r))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	len_tot += len;

	// html_footer
	len = snprintf(0, 0, "%s", html_footer);
	if(len<0)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	b = ngx_create_temp_buf(r->pool, len);
	if(b == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	b->last = ngx_sprintf(b->last, "%s", html_footer);
	if(add_ngx_buf(&cl, &ll, b, r))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	len_tot += len;

	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = len_tot;

	b->last_buf = (r == r->main) ? 1 : 0;
	b->last_in_chain = 1;

	rc = ngx_http_send_header(r);

	if(rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
		return rc;
	}

	//return NGX_HTTP_INTERNAL_SERVER_ERROR;
	//*ll = NULL;

	return ngx_http_output_filter(r, chain);
}

static ngx_int_t
ngx_mds_ok_response_handler(ngx_http_request_t *r) {
	ngx_int_t rc;
	ngx_core_conf_t *ccf;

	ngx_buf_t *b;
	ngx_chain_t *chain;
	ngx_chain_t *cl, **ll;

	ll = &chain;

	int len_tot = 0;
	int len = 0;

	//
	len = snprintf(0, 0, " ");
	if(len<0)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	b = ngx_create_temp_buf(r->pool, len);
	if(b == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	b->last = ngx_sprintf(b->last, " ");
	if(add_ngx_buf(&cl, &ll, b, r))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	len_tot += len;

	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = len_tot;

	b->last_buf = (r == r->main) ? 1 : 0;
	b->last_in_chain = 1;

	rc = ngx_http_send_header(r);

	if(rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
		return rc;
	}

	return ngx_http_output_filter(r, chain);
}

static void
_ngx_mds_reset_buf_indices(int reset_acc, int reset_log, int proc_idx, ngx_mds_main_ctx_t *ngx_mds_main_ctx, ngx_core_conf_t *ccf) {
	ngx_mds_sync_proc_t *sync_proc;
	char *buf_acc, *buf_log;

	ngx_int_t ret;

	ret = get_buf(proc_idx, &buf_acc, &sync_proc, ngx_mds_main_ctx, PHASE_ACC_IDX, 1);

	ret = get_buf(proc_idx, &buf_log, &sync_proc, ngx_mds_main_ctx, PHASE_LOG_IDX, 1);

	if(reset_acc) {
		sync_proc->phase_acc_idx = 0;
		sync_proc->phase_acc_len = 0;

		buf_acc[sync_proc->phase_acc_len] = 0;
	}

	if(reset_log) {
		sync_proc->phase_log_idx = 0;
		sync_proc->phase_log_len = 0;

		buf_log[sync_proc->phase_log_len] = 0;
	}
}

static void
ngx_mds_reset_buf_indices(int reset_acc, int reset_log, int proc_idx) {
	ngx_core_conf_t *ccf;

	ngx_mds_main_ctx_t *ngx_mds_main_ctx = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_mod_status);
	ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx, ngx_core_module);

	if(proc_idx>=0)
		return _ngx_mds_reset_buf_indices(reset_acc, reset_log, proc_idx, ngx_mds_main_ctx, ccf);

	int i;
	for(i=0; i<ccf->worker_processes; i++) {
		_ngx_mds_reset_buf_indices(reset_acc, reset_log, i, ngx_mds_main_ctx, ccf);
	}
}

static ngx_int_t
ngx_mds_handler(ngx_http_request_t *r) {
	ngx_int_t rc;
	ngx_str_t arg_cmd;
	ngx_int_t msec;
	ngx_core_conf_t *ccf;

	ngx_mds_main_ctx_t *ngx_mds_main_ctx = ngx_http_get_module_main_conf(r, ngx_mod_status);
	ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)ngx_mds_main_ctx->shm_zone->shm.addr;
	ngx_mds_sync_t *sync_zone = (ngx_mds_sync_t *)(((char *)ngx_mds_main_ctx->shm_zone->shm.addr)+sizeof(ngx_slab_pool_t));
	ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx, ngx_core_module);

	rc = ngx_mds_send_header(r, "text/html");

	if(rc!=NGX_OK)
		return rc;

	if(r->args.len) {
		if(ngx_http_arg(r, (u_char *) "cmd", 3, &arg_cmd) == NGX_OK) {
			if(arg_cmd.len == 9 && ngx_strncmp(arg_cmd.data, "start_rec", 9) == 0) {
				ngx_shmtx_lock(&shpool->mutex);
				sync_zone->record_msec_start = ngx_current_msec;
				sync_zone->is_recording = 1;
				ngx_mds_reset_buf_indices(1, 0, -1);
				ngx_shmtx_unlock(&shpool->mutex);

				return ngx_mds_ok_response_handler(r);
			}
		}

		if(ngx_http_arg(r, (u_char *) "refresh", 7, &arg_cmd) == NGX_OK) {
			ngx_shmtx_lock(&shpool->mutex);
			sync_zone->record_msec = bound_val(ngx_atoi(arg_cmd.data, arg_cmd.len), MIN_REC_MS, MAX_REC_MS);
			ngx_shmtx_unlock(&shpool->mutex);
		}

		if(ngx_http_arg(r, (u_char *) "expl", 4, &arg_cmd) == NGX_OK) {
			ngx_shmtx_lock(&shpool->mutex);
			sync_zone->expl = bound_val(ngx_atoi(arg_cmd.data, arg_cmd.len), 0, 1);
			ngx_shmtx_unlock(&shpool->mutex);
		}
	}

	return ngx_mds_stats_handler(r);
}


static ngx_int_t
ngx_mds_variable(ngx_http_request_t *r,
				 ngx_http_variable_value_t *v, uintptr_t data) {
	u_char            *p;
	ngx_atomic_int_t   value;

	p = ngx_pnalloc(r->pool, NGX_ATOMIC_T_LEN);
	if(p == NULL) {
		return NGX_ERROR;
	}

	switch(data) {
	case 0:
		value = *ngx_stat_active;
		break;

	case 1:
		value = *ngx_stat_reading;
		break;

	case 2:
		value = *ngx_stat_writing;
		break;

	case 3:
		value = *ngx_stat_waiting;
		break;

	/* suppress warning */
	default:
		value = 0;
		break;
	}

	v->len = ngx_sprintf(p, "%uA", value) - p;
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;
	v->data = p;

	return NGX_OK;
}


static ngx_int_t
ngx_mds_add_variables(ngx_conf_t *cf) {
	ngx_http_variable_t  *var, *v;

	for(v = ngx_mds_vars; v->name.len; v++) {
		var = ngx_http_add_variable(cf, &v->name, v->flags);
		if(var == NULL) {
			return NGX_ERROR;
		}

		var->get_handler = v->get_handler;
		var->data = v->data;
	}

	return NGX_OK;
}

static ngx_int_t
gen_stat_json(ngx_http_request_t *r, ngx_mds_main_ctx_t *ngx_mds_main_ctx, int *json_len) {
	ngx_connection_t *c;

	c = r->connection;

	int port_len = r->port_end - r->port_start;
	char port[port_len+1];
	memcpy(port, r->port_start, port_len);
	port[port_len] = 0;/**/
	//char* port = "";

	int remote_len = c->addr_text.len>ngx_mds_main_ctx->long_str_size-1 ? ngx_mds_main_ctx->long_str_size-1 : c->addr_text.len;
	memcpy(ngx_mds_main_ctx->buf_remote, c->addr_text.data, remote_len);
	ngx_mds_main_ctx->buf_remote[remote_len] = 0;

	int host_len = r->headers_in.server.len>ngx_mds_main_ctx->long_str_size-1 ? ngx_mds_main_ctx->long_str_size-1 : r->headers_in.server.len;
	memcpy(ngx_mds_main_ctx->buf_host, r->headers_in.server.data, host_len);
	ngx_mds_main_ctx->buf_host[host_len] = 0;

	int request_len = r->request_line.len>ngx_mds_main_ctx->long_str_size-1 ? ngx_mds_main_ctx->long_str_size-1 : r->request_line.len;
	memcpy(ngx_mds_main_ctx->buf_request, r->request_line.data, request_len);
	ngx_mds_main_ctx->buf_request[request_len] = 0;

	ngx_connection_t* conn_id = ((ngx_connection_t*)c)-((ngx_connection_t*)ngx_cycle->connections);//c;//*ngx_connection_counter;//c->number

	int len = snprintf(0, 0, stat_json,
					   conn_id, r->stat_reading ? "R" : "-", r->stat_writing ? "W" : "-", r->stat_processing ? "P" : "-", port,
					   ngx_mds_main_ctx->buf_remote, ngx_mds_main_ctx->buf_host, ngx_mds_main_ctx->buf_request);
	if(len<0)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	sprintf(ngx_mds_main_ctx->buf_stat, stat_json,
			conn_id, r->stat_reading ? "R" : "-", r->stat_writing ? "W" : "-", r->stat_processing ? "P" : "-", port,
			ngx_mds_main_ctx->buf_remote, ngx_mds_main_ctx->buf_host, ngx_mds_main_ctx->buf_request);

	*json_len = len;

	return NGX_OK;
}

static ngx_int_t
gen_stat_json_c(ngx_connection_t *c, ngx_mds_main_ctx_t *ngx_mds_main_ctx, int *json_len) {
	/*ngx_mds_main_ctx->addr_text.len = ngx_sock_ntop(c->sockaddr, c->socklen, ngx_mds_main_ctx->addr_text.data, NGX_SOCKADDR_STRLEN, 0);
	if (ngx_mds_main_ctx->addr_text.len == 0) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	int remote_len = ngx_mds_main_ctx->addr_text.len>ngx_mds_main_ctx->long_str_size-1 ? ngx_mds_main_ctx->long_str_size-1 : ngx_mds_main_ctx->addr_text.len;
	memcpy(ngx_mds_main_ctx->buf_remote, ngx_mds_main_ctx->addr_text.data, remote_len);
	ngx_mds_main_ctx->buf_remote[remote_len] = 0;*/

	int remote_len = c->addr_text.len>ngx_mds_main_ctx->long_str_size-1 ? ngx_mds_main_ctx->long_str_size-1 : c->addr_text.len;
	memcpy(ngx_mds_main_ctx->buf_remote, c->addr_text.data, remote_len);
	ngx_mds_main_ctx->buf_remote[remote_len] = 0;

	ngx_connection_t* conn_id = ((ngx_connection_t*)c)-((ngx_connection_t*)ngx_cycle->connections);//c;//*ngx_connection_counter;

	int len = snprintf(0, 0, stat_json_c, conn_id, ngx_mds_main_ctx->buf_remote);
	if(len<0)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	sprintf(ngx_mds_main_ctx->buf_stat, stat_json_c, conn_id, ngx_mds_main_ctx->buf_remote);

	*json_len = len;

	return NGX_OK;
}

static int do_exi = 0;
static ngx_int_t
ngx_mds_phase_handler(ngx_http_request_t *r, int phase_idx, int do_lock, ngx_connection_t *c, int ignore_rec) {
	ngx_mds_sync_proc_t *sync_proc = 0;
	char *buf = 0;
	int json_len;

	ngx_mds_main_ctx_t *ngx_mds_main_ctx = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_mod_status);
	ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)ngx_mds_main_ctx->shm_zone->shm.addr;

	if(ngx_mds_main_ctx == NULL) {
		return NGX_ERROR;
	}

	ngx_mds_sync_t *sync_zone = (ngx_mds_sync_t *)(((char *)ngx_mds_main_ctx->shm_zone->shm.addr)+sizeof(ngx_slab_pool_t));

	ngx_int_t ret = NGX_OK;

	if(do_lock)
		ngx_shmtx_lock(&shpool->mutex);
	//ngx_mds_shmtx_trylock(&shpool->mutex);
	//ret = ngx_shmtx_trylock(&shpool->mutex);

	if(ret!=NGX_OK) {
		return NGX_OK;
	}

	ngx_int_t msec = ngx_current_msec;

	ngx_mds_try_stop_rec(sync_zone, msec);

	ret = get_buf(ngx_process_slot, &buf, &sync_proc, ngx_mds_main_ctx, phase_idx, 0);

	if(ret!=NGX_OK) {
		if(do_lock)
			ngx_shmtx_unlock(&shpool->mutex);

		return NGX_OK;
	}

	ngx_int_t is_recording = sync_zone->is_recording;
	ngx_int_t _phase_idx = phase_idx==PHASE_ACC_IDX ? sync_proc->phase_acc_idx : sync_proc->phase_log_idx;

	if(do_lock)
		ngx_shmtx_unlock(&shpool->mutex);

	if(!is_recording && !ignore_rec)
		return NGX_OK;

	if(_phase_idx>=ngx_mds_main_ctx->msg_count)
		return NGX_OK;

	if(c)
		ret = gen_stat_json_c(c, ngx_mds_main_ctx, &json_len);
	else
		ret = gen_stat_json(r, ngx_mds_main_ctx, &json_len);/**/

	if(ret!=NGX_OK) {
		return NGX_OK;
	}

	ret = NGX_OK;

	//ngx_shmtx_lock(&ngx_mds_mutex);
	if(do_lock)
		ngx_shmtx_lock(&shpool->mutex);
	//ret = ngx_mds_shmtx_trylock(&shpool->mutex);
	//ret = ngx_shmtx_trylock(&shpool->mutex);

	if(ret!=NGX_OK) {
		return NGX_OK;
	}

	msec = ngx_current_msec;

	ngx_mds_try_stop_rec(sync_zone, msec);

	if((sync_zone->is_recording || (!sync_zone->is_recording && ignore_rec)) &&
			((phase_idx==PHASE_ACC_IDX && _phase_idx==sync_proc->phase_acc_idx) || (phase_idx==PHASE_LOG_IDX && _phase_idx==sync_proc->phase_log_idx))) {

		memcpy(buf, ngx_mds_main_ctx->buf_stat, json_len);

		ret = get_buf(ngx_process_slot, &buf, &sync_proc, ngx_mds_main_ctx, phase_idx, 1);
		if(ret!=NGX_OK) {
			if(do_lock)
				ngx_shmtx_unlock(&shpool->mutex);

			return NGX_OK;
		}

		if(phase_idx==PHASE_ACC_IDX) {
			sync_proc->phase_acc_idx++;
			sync_proc->phase_acc_len += json_len;
		} else {
			sync_proc->phase_log_idx++;
			sync_proc->phase_log_len += json_len;
		}

		if(phase_idx==PHASE_ACC_IDX && sync_proc->phase_acc_idx<ngx_mds_main_ctx->msg_count) {
			buf[sync_proc->phase_acc_len++] = ',';
		} else if(phase_idx==PHASE_LOG_IDX && sync_proc->phase_log_idx<ngx_mds_main_ctx->msg_count) {
			buf[sync_proc->phase_log_len++] = ',';
		}



		buf[phase_idx==PHASE_ACC_IDX ? sync_proc->phase_acc_len : sync_proc->phase_log_len] = 0;

	}

	//ngx_shmtx_unlock(&ngx_mds_mutex);
	if(do_lock)
		ngx_shmtx_unlock(&shpool->mutex);

	return NGX_OK;
}

static ngx_int_t
ngx_mds_access_handler(ngx_http_request_t *r) {
	return ngx_mds_phase_handler(r, PHASE_ACC_IDX, 1, 0, 0);
}

static ngx_int_t
ngx_mds_post_read_handler(ngx_http_request_t *r) {
	ngx_connection_t *c;

	c = r->connection;

	ngx_mds_main_ctx_t *ngx_mds_main_ctx = ngx_http_get_module_main_conf(r, ngx_mod_status);

	int bit_pos = ((ngx_connection_t*)c)-((ngx_connection_t*)ngx_cycle->connections);

	ngx_mds_main_ctx->bmp_acc[BMP_POS(bit_pos)] |= BMP_SET(bit_pos);
	ngx_mds_main_ctx->bmp_log[BMP_POS(bit_pos)] &= BMP_CLR(bit_pos);

	return NGX_OK;
}

static ngx_int_t
ngx_mds_log_handler(ngx_http_request_t *r) {
	ngx_connection_t *c;

	c = r->connection;

	ngx_mds_main_ctx_t *ngx_mds_main_ctx = ngx_http_get_module_main_conf(r, ngx_mod_status);

	int bit_pos = ((ngx_connection_t*)c)-((ngx_connection_t*)ngx_cycle->connections);

	ngx_mds_main_ctx->bmp_acc[BMP_POS(bit_pos)] &= BMP_CLR(bit_pos);

	return NGX_OK;
}

static ngx_int_t
ngx_mds_postconf(ngx_conf_t *cf) {
	ngx_mds_main_ctx_t *ngx_mds_main_ctx = ngx_http_conf_get_module_main_conf(cf, ngx_mod_status);

	ngx_http_handler_pt        *h;
	ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
	if(h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_mds_access_handler;/**/

	if(!ngx_mds_main_ctx->has_mds_epoll) {
		h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
		if(h == NULL) {
			return NGX_ERROR;
		}

		*h = ngx_mds_post_read_handler;

	}

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
	if(h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_mds_log_handler;


	return NGX_OK;
}

static ngx_int_t
ngx_mds_zone_init(ngx_shm_zone_t *shm_zone, void *data) {
	memset(((char *)shm_zone->shm.addr+sizeof(ngx_slab_pool_t)), 0, shm_zone->shm.size-sizeof(ngx_slab_pool_t));
	return NGX_OK;
}

static void *
ngx_mds_create_main_conf(ngx_conf_t *cf) {
	ngx_mds_main_ctx_t *ngx_mds_main_ctx = ngx_http_conf_get_module_main_conf(cf, ngx_mod_status);

	ngx_mds_main_ctx = ngx_pcalloc(cf->pool, sizeof(ngx_mds_main_ctx_t));

	if(ngx_mds_main_ctx == NULL) {
		return NULL;
	}

	ngx_mds_main_ctx->msg_size = DFT_MSG_SIZE;
	ngx_mds_main_ctx->msg_count = DFT_MSG_CNT;

	ngx_mds_main_ctx->has_mds_epoll = 0;


	return ngx_mds_main_ctx;
}

static char *
ngx_mds_init_main_conf(ngx_conf_t *cf, void *conf) {
	ngx_core_conf_t *ccf;
	ssize_t size;

	ccf = (ngx_core_conf_t *) ngx_get_conf(cf->cycle->conf_ctx, ngx_core_module);

	ngx_mds_main_ctx_t *ngx_mds_main_ctx = ngx_http_conf_get_module_main_conf(cf, ngx_mod_status);

	if(ngx_mds_main_ctx == NULL) {
		return NGX_CONF_ERROR;
	}

	ngx_str_t name;
	ngx_str_set(&name, SHM_NAME);

	// > 703
	size = ccf->worker_processes*(sizeof(ngx_mds_sync_proc_t)+ngx_mds_main_ctx->msg_size*ngx_mds_main_ctx->msg_count*PHASE_CNT)+sizeof(ngx_mds_sync_t)+
		   sizeof(ngx_slab_pool_t);
	ngx_shm_zone_t *shm_zone = ngx_shared_memory_add(cf, &name, size,
							   &ngx_mod_status);

	if(shm_zone == NULL) {
		return NGX_CONF_ERROR;
	}

	shm_zone->init = ngx_mds_zone_init;
	shm_zone->data = NULL;

	//
	int len_empty_stat_json = snprintf(0, 0, stat_json, "", "", "", "", "", "", "", "");
	int len_const = ID_SZ+PH_SZ*3+PORT_SZ;

	if(len_empty_stat_json+len_const>ngx_mds_main_ctx->msg_size) {
		ngx_log_error(NGX_LOG_ERR, cf->cycle->log, 0, "set message size greater than %d", len_empty_stat_json+len_const);
		return NGX_CONF_ERROR;
	}

	int long_str_size = (ngx_mds_main_ctx->msg_size-(len_empty_stat_json+len_const)-5)/3;

	char *buf = ngx_pcalloc(cf->pool, ngx_mds_main_ctx->msg_size);
	if(buf==NULL)
		return NGX_CONF_ERROR;
	ngx_mds_main_ctx->buf_stat = buf;

	buf = ngx_pcalloc(cf->pool, long_str_size);
	if(buf==NULL)
		return NGX_CONF_ERROR;
	ngx_mds_main_ctx->buf_remote = buf;

	buf = ngx_pcalloc(cf->pool, long_str_size);
	if(buf==NULL)
		return NGX_CONF_ERROR;
	ngx_mds_main_ctx->buf_host = buf;

	buf = ngx_pcalloc(cf->pool, long_str_size);
	if(buf==NULL)
		return NGX_CONF_ERROR;
	ngx_mds_main_ctx->buf_request = buf;

	buf = ngx_pcalloc(cf->pool, sizeof(ngx_http_request_t));
	if(buf==NULL)
		return NGX_CONF_ERROR;
	ngx_mds_main_ctx->r = buf;

	buf = ngx_pcalloc(cf->pool, BMP_SZ(cf->cycle->connection_n));
	if(buf==NULL)
		return NGX_CONF_ERROR;
	ngx_mds_main_ctx->bmp_acc = buf;
	memset(ngx_mds_main_ctx->bmp_acc, 0, BMP_SZ(cf->cycle->connection_n));

	buf = ngx_pcalloc(cf->pool, BMP_SZ(cf->cycle->connection_n));
	if(buf==NULL)
		return NGX_CONF_ERROR;
	ngx_mds_main_ctx->bmp_log = buf;
	memset(ngx_mds_main_ctx->bmp_log, 0, BMP_SZ(cf->cycle->connection_n));

	ngx_mds_main_ctx->long_str_size = long_str_size;

	//
	ngx_mds_main_ctx->shm_zone = shm_zone;

	//
	ngx_module_t *module;

	int i;
	for(i = 0; cf->cycle->modules[i]; i++) {
		module = cf->cycle->modules[i];

		if(ngx_strcmp(module->name, "ngx_mds_epoll") == 0) {
			ngx_mds_main_ctx->has_mds_epoll = 1;

			break;
		}

	}

	return NGX_CONF_OK;
}


static char *
ngx_mds_set_commands(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http_core_loc_conf_t  *clcf;
	ngx_str_t *value;

	ngx_mds_main_ctx_t *ngx_mds_main_ctx = ngx_http_conf_get_module_main_conf(cf, ngx_mod_status);

	value = cf->args->elts;
	if(!strcmp(value[0].data, CMD_MSG_HNDL)) {
		clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
		clcf->handler = ngx_mds_handler;
	} else if(!strcmp(value[0].data, CMD_MSG_SIZE) && cf->args->nelts == 2) {
		ngx_mds_main_ctx->msg_size = ngx_atoi(value[1].data, value[1].len);
	} else if(!strcmp(value[0].data, CMD_MSG_CNT) && cf->args->nelts == 2) {
		ngx_mds_main_ctx->msg_count = ngx_atoi(value[1].data, value[1].len);
	}

	return NGX_CONF_OK;
}
