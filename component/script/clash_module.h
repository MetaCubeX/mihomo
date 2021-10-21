#ifndef CLASH_CALLBACK_MODULE_H__
#define CLASH_CALLBACK_MODULE_H__

#include <Python.h>

#define CLASH_SCRIPT_MODULE_NAME "clash_script"

struct Metadata {
    const char *type; /* type socks5/http */
    const char *network;  /* network tcp/udp */
    const char *process_name;
    const char *host;
    const char *src_ip;
    unsigned short src_port;
    const char *dst_ip;
    unsigned short dst_port;
};

/** callback function, that call go function by python3 script. **/
typedef const char *(*resolve_ip_callback)(const char *host);
typedef const char *(*geoip_callback)(const char *ip);
typedef const int (*rule_provider_callback)(const char *provider_name, struct Metadata *metadata);
typedef void (*log_callback)(const char *msg);

void set_resolve_ip_callback(resolve_ip_callback cb);
void set_geoip_callback(geoip_callback cb);
void set_rule_provider_callback(rule_provider_callback cb);
void set_log_callback(log_callback cb);
/*---------------------------------------------------------------*/

void append_inittab();
void init_python(const char *path);
void load_main_func();
void finalize_Python();
void py_clear(PyObject *obj);
const char *py_last_error();

PyObject *load_func(const char *module_name, char *func_name);

int new_clash_py_context(const char *provider_name_arr[], int size);

const char *call_main(
                const char *type,
                const char *network,
                const char *process_name,
                const char *host,
                const char *src_ip,
                unsigned short src_port,
                const char *dst_ip,
                unsigned short dst_port);

int call_shortcut(PyObject *shortcut_fn,
                const char *type,
                const char *network,
                const char *process_name,
                const char *host,
                const char *src_ip,
                unsigned short src_port,
                const char *dst_ip,
                unsigned short dst_port);

#endif // CLASH_CALLBACK_MODULE_H__