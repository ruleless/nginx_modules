#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>


typedef struct {
    ngx_flag_t enable;
    ngx_str_t redirect_uri;
} ngx_http_dyn_rewrite_loc_conf_t;

static ngx_int_t ngx_http_dyn_rewrite_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_dyn_rewrite_init(ngx_conf_t *cf);
static void *ngx_http_dyn_rewrite_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_dyn_rewrite_merge_loc_conf(ngx_conf_t *cf,
                                                 void *parent, void *child);


static ngx_http_variable_t  ngx_http_socks_vars[] = {
    { ngx_string("original_uri"), NULL, ngx_http_dyn_rewrite_origin_uri_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_command_t ngx_http_dyn_rewrite_commands[] = {
    { ngx_string("dyn_rewrite_enable"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_dyn_rewrite_loc_conf_t, enable),
      NULL },

    { ngx_string("dyn_rewrite_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_dyn_rewrite_loc_conf_t, redirect_uri),
      NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_dyn_rewrite_module_ctx = {
    ngx_http_dyn_rewrite_add_variables,    /* preconfiguration */
    ngx_http_dyn_rewrite_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_dyn_rewrite_create_loc_conf,  /* create location configuration */
    ngx_http_dyn_rewrite_merge_loc_conf    /* merge location configuration */
};

ngx_module_t ngx_http_dyn_rewrite_module = {
    NGX_MODULE_V1,
    &ngx_http_dyn_rewrite_module_ctx,      /* module context */
    ngx_http_dyn_rewrite_commands,         /* module directives */
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


static ngx_int_t
ngx_http_dyn_rewrite_handler(ngx_http_request_t *r)
{
    ngx_http_dyn_rewrite_loc_conf_t *rlcf;

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_dyn_rewrite_module);
    if (rlcf == NULL || !rlcf->enable || rlcf->redirect_uri.len == 0) {
        return NGX_DECLINED;
    }

    r->uri = rlcf->redirect_uri;
    if (r->uri.len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "the rewritten URI has a zero length");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_exten(r);

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_dyn_rewrite_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var, *v;

    for (v = ngx_http_dyn_rewrite_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dyn_rewrite_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_SERVER_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_dyn_rewrite_handler;

    return NGX_OK;
}

static void *
ngx_http_dyn_rewrite_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_dyn_rewrite_loc_conf_t *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_dyn_rewrite_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    ngx_str_null(&conf->redirect_uri);

    return conf;
}

static char *
ngx_http_dyn_rewrite_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_dyn_rewrite_loc_conf_t *prev = parent;
    ngx_http_dyn_rewrite_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->redirect_uri, prev->redirect_uri, "");

    return NGX_CONF_OK;
}
