
#ifndef __NGX_MOD_STATUS_H__
#define __NGX_MOD_STATUS_H__

typedef struct {
	ngx_shm_zone_t *shm_zone;
	ngx_int_t msg_size;
	ngx_int_t msg_count;
	ngx_event_t ev_con;

	char *buf_stat;
	char *buf_remote;
	char *buf_host;
	char *buf_request;

	ngx_http_request_t *r;

	int* bmp_acc;
	int* bmp_log;

	ngx_int_t has_mds_epoll;

	ngx_str_t addr_text;

	ngx_int_t long_str_size;
} ngx_mds_main_ctx_t;

typedef struct {
	//ngx_shmtx_sh_t shm_mutex;
	ngx_int_t is_recording;
	ngx_uint_t record_msec;
	ngx_uint_t record_msec_start;
	ngx_uint_t record_msec_elapsed;

	ngx_uint_t expl;
} ngx_mds_sync_t;

typedef struct {
	ngx_int_t phase_acc_idx;
	ngx_int_t phase_log_idx;
	ngx_int_t phase_acc_len;
	ngx_int_t phase_log_len;
	ngx_int_t pid;
} ngx_mds_sync_proc_t;

#define BMP_WRD_SZ (sizeof(int))
#define BMP_SZ(BITS) ((BITS/(BMP_WRD_SZ*8)+1)*BMP_WRD_SZ)
#define BMP_GET(BMP, POS) (BMP[POS/(BMP_WRD_SZ*8)]&(1<<(POS%(BMP_WRD_SZ*8))))
#define BMP_SET(POS) (1<<(POS%(BMP_WRD_SZ*8)))
#define BMP_CLR(POS) (~(1<<(POS%(BMP_WRD_SZ*8))))
#define BMP_POS(BITS) (BITS/(BMP_WRD_SZ*8))

#endif
