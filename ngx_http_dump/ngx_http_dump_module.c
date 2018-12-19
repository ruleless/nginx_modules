#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_flag_t  dump_all;
} ngx_http_dump_loc_conf_t;


static ngx_int_t ngx_http_dump_init(ngx_conf_t *cf);
static void *ngx_http_dump_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_dump_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);


static ngx_command_t ngx_http_dump_commands[] = {
    { ngx_string("dump_all"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_dump_loc_conf_t, dump_all),
      NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_dump_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_dump_init,                    /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_dump_create_loc_conf,         /* create location configuration */
    ngx_http_dump_merge_loc_conf           /* merge location configuration */
};

ngx_module_t ngx_http_dump_module = {
    NGX_MODULE_V1,
    &ngx_http_dump_module_ctx,             /* module context */
    ngx_http_dump_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_dump_header_filter(ngx_http_request_t *r)
{
    return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_dump_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    return ngx_http_next_body_filter(r, in);
}

static ngx_int_t
ngx_http_dump_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_dump_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_dump_body_filter;

    return NGX_OK;
}

static void *
ngx_http_dump_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_dump_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dump_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->dump_all = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_dump_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_dump_loc_conf_t *prev = parent;
    ngx_http_dump_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->dump_all, prev->dump_all, 0);

    return NGX_CONF_OK;
}
