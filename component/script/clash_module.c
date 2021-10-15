#define PY_SSIZE_T_CLEAN

#include "clash_module.h"
#include <structmember.h>

PyObject *clash_module;
PyObject *main_fn;
PyObject *clash_context;

// init_python
void init_python(const char *path) {

    append_inittab();

    Py_Initialize();

    wchar_t *program = Py_DecodeLocale("clash", NULL);
    if (program != NULL) {
        Py_SetProgramName(program);
        PyMem_RawFree(program);
    }

//    wchar_t *newPath = Py_DecodeLocale(path, NULL);
//    if (newPath != NULL) {
//        Py_SetPath(newPath);
//    }

    char *pathPrefix = "import sys; sys.path.append('";
    char *pathSuffix = "')";
    char *newPath = (char *) malloc(strlen(pathPrefix) + strlen(path) + strlen(pathSuffix));
    sprintf(newPath, "%s%s%s", pathPrefix, path, pathSuffix);

    PyRun_SimpleString(newPath);
    free(newPath);

    /* Optionally import the module; alternatively,
        import can be deferred until the embedded script
        imports it. */
    clash_module = PyImport_ImportModule("clash");

    main_fn = load_func(CLASH_SCRIPT_MODULE_NAME, "main");
}

// Load function, same as "import module_name.func_name as obj" in Python
// Returns the function object or NULL if not found
PyObject *load_func(const char *module_name, char *func_name) {
    // Import the module
    PyObject *py_mod_name = PyUnicode_FromString(module_name);
    if (py_mod_name == NULL) {
        return NULL;
    }

    PyObject *module = PyImport_Import(py_mod_name);
    Py_DECREF(py_mod_name);
    if (module == NULL) {
        return NULL;
    }

    // Get function, same as "getattr(module, func_name)" in Python
    PyObject *func = PyObject_GetAttrString(module, func_name);
    Py_DECREF(module);
    return func;
}

// Return last error as char *, NULL if there was no error
const char *py_last_error() {
    PyObject *err = PyErr_Occurred();
    if (err == NULL) {
        return NULL;
    }

    PyObject *type, *value, *traceback;
    PyErr_Fetch(&type, &value, &traceback);

    if (value == NULL) {
        return NULL;
    }

    PyObject *str = PyObject_Str(value);
    const char *utf8 = PyUnicode_AsUTF8(str);
    Py_DECREF(str);
    PyErr_Clear();
    return utf8;
}

void py_clear(PyObject *obj) {
    Py_CLEAR(obj);
}

/** callback function, that call go function by python3 script. **/

resolve_ip_callback resolve_ip_callback_fn;

geoip_callback geoip_callback_fn;

rule_provider_callback rule_provider_callback_fn;

log_callback log_callback_fn;

void
set_resolve_ip_callback(resolve_ip_callback cb)
{
    resolve_ip_callback_fn = cb;
}

void
set_geoip_callback(geoip_callback cb)
{
    geoip_callback_fn = cb;
}

void
set_rule_provider_callback(rule_provider_callback cb)
{
    rule_provider_callback_fn = cb;
}

void
set_log_callback(log_callback cb)
{
    log_callback_fn = cb;
}

/** end callback function **/

/* --------------------------------------------------------------------- */

/* RuleProvider objects */

typedef struct {
    PyObject_HEAD
    PyObject *name; /* rule provider name */
} RuleProviderObject;

static int
RuleProvider_traverse(RuleProviderObject *self, visitproc visit, void *arg)
{
    Py_VISIT(self->name);
    return 0;
}

static int
RuleProvider_clear(RuleProviderObject *self)
{
    Py_CLEAR(self->name);
    return 0;
}

static void
RuleProvider_dealloc(RuleProviderObject *self)
{
    PyObject_GC_UnTrack(self);
    RuleProvider_clear(self);
    Py_TYPE(self)->tp_free((PyObject *) self);
}

static PyObject *
RuleProvider_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    RuleProviderObject *self;
    self = (RuleProviderObject *) type->tp_alloc(type, 0);
    if (self != NULL) {
        self->name = PyUnicode_FromString("");
        if (self->name == NULL) {
            Py_DECREF(self);
            return NULL;
        }
    }
    return (PyObject *) self;
}

static int
RuleProvider_init(RuleProviderObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"name", NULL};
    PyObject *name = NULL, *tmp;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|Us", kwlist, &name))
        return -1;

    if (name) {
        tmp = self->name;
        Py_INCREF(name);
        self->name = name;
        Py_DECREF(tmp);
    }
    return 0;
}

//static PyMemberDef RuleProvider_members[] = {
//    {"adapter_type", T_STRING, offsetof(RuleProviderObject, adapter_type), 0,
//     "adapter type"},
//    {NULL}  /* Sentinel */
//};

static PyObject *
RuleProvider_getname(RuleProviderObject *self, void *closure)
{
    Py_INCREF(self->name);
    return self->name;
}

static int
RuleProvider_setname(RuleProviderObject *self, PyObject *value, void *closure)
{
    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete the name attribute");
        return -1;
    }
    if (!PyUnicode_Check(value)) {
        PyErr_SetString(PyExc_TypeError,
            "The name attribute value must be a string");
        return -1;
    }
    Py_INCREF(value);
    Py_CLEAR(self->name);
    self->name = value;
    return 0;
}

static PyGetSetDef RuleProvider_getsetters[] = {
    {"name", (getter) RuleProvider_getname, (setter) RuleProvider_setname,
     "name", NULL},
    {NULL}  /* Sentinel */
};

static PyObject *
RuleProvider_name(RuleProviderObject *self, PyObject *Py_UNUSED(ignored))
{
    Py_INCREF(self->name);
    return self->name;
}

static PyObject *
RuleProvider_match(RuleProviderObject *self, PyObject *args)
{
    PyObject *result;
    PyObject *tmp;
    const char *provider_name;

    if (!PyArg_ParseTuple(args, "O!", &PyDict_Type, &tmp)) //Format "O","O!","O&": Borrowed reference.
        return NULL;

    if (tmp == NULL)
        Py_RETURN_FALSE;

    Py_INCREF(tmp);
//    PyObject *py_src_port = PyDict_GetItemString(tmp, "src_port"); //Return value: Borrowed reference.
//    PyObject *py_dst_port = PyDict_GetItemString(tmp, "dst_port"); //Return value: Borrowed reference.
//    Py_INCREF(py_src_port);
//    Py_INCREF(py_dst_port);
//    char *c_src_port = (char *) malloc(PyLong_AsSize_t(py_src_port));
//    char *c_dst_port = (char *) malloc(PyLong_AsSize_t(py_dst_port));
//    sprintf(c_src_port, "%ld", PyLong_AsLong(py_src_port));
//    sprintf(c_dst_port, "%ld", PyLong_AsLong(py_dst_port));

    struct Metadata metadata = {
        .type = PyUnicode_AsUTF8(PyDict_GetItemString(tmp, "type")), // PyDict_GetItemString() Return value: Borrowed reference.
        .network = PyUnicode_AsUTF8(PyDict_GetItemString(tmp, "network")),
        .process_name = PyUnicode_AsUTF8(PyDict_GetItemString(tmp, "process_name")),
        .host = PyUnicode_AsUTF8(PyDict_GetItemString(tmp, "host")),
        .src_ip = PyUnicode_AsUTF8(PyDict_GetItemString(tmp, "src_ip")),
        .src_port = (unsigned short)PyLong_AsUnsignedLong(PyDict_GetItemString(tmp, "src_port")),
        .dst_ip = PyUnicode_AsUTF8(PyDict_GetItemString(tmp, "dst_ip")),
        .dst_port = (unsigned short)PyLong_AsUnsignedLong(PyDict_GetItemString(tmp, "dst_port"))
    };

//    Py_DECREF(py_src_port);
//    Py_DECREF(py_dst_port);

    Py_INCREF(self->name);
    provider_name = PyUnicode_AsUTF8(self->name);
    Py_DECREF(self->name);
    Py_DECREF(tmp);

    int rs = rule_provider_callback_fn(provider_name, &metadata);

    result = (rs == 1) ? Py_True : Py_False;
    Py_INCREF(result);
    return result;
}

static PyMethodDef RuleProvider_methods[] = {
    {"name", (PyCFunction) RuleProvider_name, METH_NOARGS,
     "Return the RuleProvider name"
    },
    {"match", (PyCFunction) RuleProvider_match, METH_VARARGS,
     "Match the rule by the RuleProvider, match(metadata) -> boolean"
    },
    {NULL}  /* Sentinel */
};

static PyTypeObject RuleProviderType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "clash.RuleProvider",
    .tp_doc = "Clash RuleProvider objects",
    .tp_basicsize = sizeof(RuleProviderObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,
    .tp_new = RuleProvider_new,
    .tp_init = (initproc) RuleProvider_init,
    .tp_dealloc = (destructor) RuleProvider_dealloc,
    .tp_traverse = (traverseproc) RuleProvider_traverse,
    .tp_clear = (inquiry) RuleProvider_clear,
//    .tp_members = RuleProvider_members,
    .tp_methods = RuleProvider_methods,
    .tp_getset = RuleProvider_getsetters,
};

/* end RuleProvider objects */
/* --------------------------------------------------------------------- */

/* Context objects */

typedef struct {
    PyObject_HEAD
    PyObject *rule_providers; /* Dict<String, RuleProvider> */
} ContextObject;

static int
Context_traverse(ContextObject *self, visitproc visit, void *arg)
{
    Py_VISIT(self->rule_providers);
    return 0;
}

static int
Context_clear(ContextObject *self)
{
    Py_CLEAR(self->rule_providers);
    return 0;
}

static void
Context_dealloc(ContextObject *self)
{
    PyObject_GC_UnTrack(self);
    Context_clear(self);
    Py_TYPE(self)->tp_free((PyObject *) self);
}

static PyObject *
Context_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    ContextObject *self;
    self = (ContextObject *) type->tp_alloc(type, 0);
    if (self != NULL) {
        self->rule_providers = PyDict_New();
        if (self->rule_providers == NULL) {
            Py_DECREF(self);
            return NULL;
        }
    }
    return (PyObject *) self;
}

static int
Context_init(ContextObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"rule_providers", NULL};
    PyObject *rule_providers = NULL, *tmp;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O", kwlist,
                                     &rule_providers))
        return -1;

    if (rule_providers) {
        tmp = self->rule_providers;
        Py_INCREF(rule_providers);
        self->rule_providers = rule_providers;
        Py_DECREF(tmp);
    }
    return 0;
}

static PyObject *
Context_getrule_providers(ContextObject *self, void *closure)
{
    Py_INCREF(self->rule_providers);
    return self->rule_providers;
}

static int
Context_setrule_providers(ContextObject *self, PyObject *value, void *closure)
{
    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete the rule_providers attribute");
        return -1;
    }
    if (!PyDict_Check(value)) {
        PyErr_SetString(PyExc_TypeError,
            "The rule_providers attribute value must be a dict");
        return -1;
    }
    Py_INCREF(value);
    Py_CLEAR(self->rule_providers);
    self->rule_providers = value;
    return 0;
}

static PyGetSetDef Context_getsetters[] = {
    {"rule_providers", (getter) Context_getrule_providers, (setter) Context_setrule_providers,
     "rule_providers", NULL},
    {NULL}  /* Sentinel */
};

static PyObject *
Context_resolve_ip(PyObject *self, PyObject *args)
{
    const char *host;
    const char *ip;

    if (!PyArg_ParseTuple(args, "s", &host))
        return NULL;

    if (host == NULL)
        return PyUnicode_FromString("");

    ip = resolve_ip_callback_fn(host);

    return PyUnicode_FromString(ip);
}

static PyObject *
Context_geoip(PyObject *self, PyObject *args)
{
    const char *ip;
    const char *countryCode;

    if (!PyArg_ParseTuple(args, "s", &ip))
        return NULL;

    if (ip == NULL)
        return PyUnicode_FromString("");

    countryCode = geoip_callback_fn(ip);

    return PyUnicode_FromString(countryCode);
}

static PyObject *
Context_log(PyObject *self, PyObject *args)
{
    const char *msg;

    if (!PyArg_ParseTuple(args, "s", &msg))
        return NULL;

    log_callback_fn(msg);

    Py_RETURN_NONE;
}

static PyMethodDef Context_methods[] = {
    {"resolve_ip", (PyCFunction) Context_resolve_ip, METH_VARARGS,
     "resolve_ip(host) -> string"
    },
    {"geoip", (PyCFunction) Context_geoip, METH_VARARGS,
     "geoip(ip) -> string"
    },
    {"log", (PyCFunction) Context_log, METH_VARARGS,
     "log(msg) -> void"
    },
    {NULL}  /* Sentinel */
};

static PyTypeObject ContextType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "clash.Context",
    .tp_doc = "Clash Context objects",
    .tp_basicsize = sizeof(ContextObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,
    .tp_new = Context_new,
    .tp_init = (initproc) Context_init,
    .tp_dealloc = (destructor) Context_dealloc,
    .tp_traverse = (traverseproc) Context_traverse,
    .tp_clear = (inquiry) Context_clear,
    .tp_methods = Context_methods,
    .tp_getset = Context_getsetters,
};

static PyModuleDef clashmodule = {
    PyModuleDef_HEAD_INIT,
    .m_name = "clash",
    .m_doc = "Clash module that creates an extension module for python3.",
    .m_size = -1,
};

PyMODINIT_FUNC
PyInit_clash(void)
{
    PyObject *m;

    m = PyModule_Create(&clashmodule);
    if (m == NULL)
        return NULL;

    if (PyType_Ready(&RuleProviderType) < 0)
        return NULL;

    Py_INCREF(&RuleProviderType);
    if (PyModule_AddObject(m, "RuleProvider", (PyObject *) &RuleProviderType) < 0) {
        Py_DECREF(&RuleProviderType);
        Py_DECREF(m);
        return NULL;
    }

    if (PyType_Ready(&ContextType) < 0)
        return NULL;

    Py_INCREF(&ContextType);
    if (PyModule_AddObject(m, "Context", (PyObject *) &ContextType) < 0) {
        Py_DECREF(&ContextType);
        Py_DECREF(m);
        return NULL;
    }

    return m;
}

/* end Context objects */

/* --------------------------------------------------------------------- */

void
append_inittab()
{
    /* Add a built-in module, before Py_Initialize */
    PyImport_AppendInittab("clash", PyInit_clash);
}

int new_clash_py_context(const char *provider_name_arr[], int size) {
    PyObject *dict = PyDict_New(); //Return value: New reference.
    if (dict == NULL) {
        PyErr_SetString(PyExc_TypeError,
            "PyDict_New failure");
        return 0;
    }

    for (int i = 0; i < size; i++) {
        PyObject *rule_provider = RuleProvider_new(&RuleProviderType, NULL, NULL);
        if (rule_provider == NULL) {
            Py_DECREF(dict);
            PyErr_SetString(PyExc_TypeError,
                    "RuleProvider_new failure");
            return 0;
        }

        RuleProviderObject *providerObj = (RuleProviderObject *) rule_provider;

        PyObject *py_name = PyUnicode_FromString(provider_name_arr[i]); //Return value: New reference.
        RuleProvider_setname(providerObj, py_name, NULL);
        Py_DECREF(py_name);

        PyDict_SetItemString(dict, provider_name_arr[i], rule_provider); //Parameter value: New reference.
        Py_DECREF(rule_provider);
    }

    clash_context = Context_new(&ContextType, NULL, NULL);

    if (clash_context == NULL) {
        Py_DECREF(dict);
        PyErr_SetString(PyExc_TypeError,
                "Context_new failure");
        return 0;
    }

    Context_setrule_providers((ContextObject *) clash_context, dict, NULL);
    Py_DECREF(dict);
    return 1;
}

const char *call_main(
                const char *type,
                const char *network,
                const char *process_name,
                const char *host,
                const char *src_ip,
                unsigned short src_port,
                const char *dst_ip,
                unsigned short dst_port) {

    PyObject *metadataDict;
    PyObject *tupleArgs;
    PyObject *result;

    metadataDict = PyDict_New(); //Return value: New reference.

    if (metadataDict == NULL) {
        PyErr_SetString(PyExc_TypeError,
            "PyDict_New failure");
        return "-1";
    }

    PyObject *p_type = PyUnicode_FromString(type); //Return value: New reference.
    PyObject *p_network = PyUnicode_FromString(network); //Return value: New reference.
    PyObject *p_process_name = PyUnicode_FromString(process_name); //Return value: New reference.
    PyObject *p_host = PyUnicode_FromString(host); //Return value: New reference.
    PyObject *p_src_ip = PyUnicode_FromString(src_ip); //Return value: New reference.
    PyObject *p_src_port = PyLong_FromUnsignedLong((unsigned long)src_port); //Return value: New reference.
    PyObject *p_dst_ip = PyUnicode_FromString(dst_ip); //Return value: New reference.
    PyObject *p_dst_port = PyLong_FromUnsignedLong((unsigned long)dst_port); //Return value: New reference.

    PyDict_SetItemString(metadataDict, "type", p_type); //Parameter value: New reference.
    PyDict_SetItemString(metadataDict, "network", p_network); //Parameter value: New reference.
    PyDict_SetItemString(metadataDict, "process_name", p_process_name); //Parameter value: New reference.
    PyDict_SetItemString(metadataDict, "host", p_host); //Parameter value: New reference.
    PyDict_SetItemString(metadataDict, "src_ip", p_src_ip); //Parameter value: New reference.
    PyDict_SetItemString(metadataDict, "src_port", p_src_port); //Parameter value: New reference.
    PyDict_SetItemString(metadataDict, "dst_ip", p_dst_ip); //Parameter value: New reference.
    PyDict_SetItemString(metadataDict, "dst_port", p_dst_port); //Parameter value: New reference.

    Py_DECREF(p_type);
    Py_DECREF(p_network);
    Py_DECREF(p_process_name);
    Py_DECREF(p_host);
    Py_DECREF(p_src_ip);
    Py_DECREF(p_src_port);
    Py_DECREF(p_dst_ip);
    Py_DECREF(p_dst_port);

    tupleArgs = PyTuple_New(2); //Return value: New reference.
    if (tupleArgs == NULL) {
        Py_DECREF(metadataDict);
        PyErr_SetString(PyExc_TypeError,
            "PyTuple_New failure");
        return "-1";
    }

    Py_INCREF(clash_context);
    PyTuple_SetItem(tupleArgs, 0, clash_context); //clash_context Parameter value: Stolen reference.
    PyTuple_SetItem(tupleArgs, 1, metadataDict); //metadataDict Parameter value: Stolen reference.

    Py_INCREF(main_fn);
    result = PyObject_CallObject(main_fn, tupleArgs); //Return value: New reference.
    Py_DECREF(main_fn);
    Py_DECREF(tupleArgs);

    if (result == NULL) {
        return "-1";
    }

    if (!PyUnicode_Check(result)) {
        Py_DECREF(result);
        PyErr_SetString(PyExc_TypeError,
            "script main function return value must be a string");
        return "-1";
    }

    const char *adapter = PyUnicode_AsUTF8(result);

    Py_DECREF(result);

    return adapter;
}

int call_shortcut(PyObject *shortcut_fn,
                const char *type,
                const char *network,
                const char *process_name,
                const char *host,
                const char *src_ip,
                unsigned short src_port,
                const char *dst_ip,
                unsigned short dst_port) {

    PyObject *args;
    PyObject *result;

    args = Py_BuildValue("{s:O, s:s, s:s, s:s, s:s, s:H, s:s, s:H}",
                        "ctx", clash_context,
                        "network", network,
                        "process_name", process_name,
                        "host", host,
                        "src_ip", src_ip,
                        "src_port", src_port,
                        "dst_ip", dst_ip,
                        "dst_port", dst_port); //Return value: New reference.

    if (args == NULL) {
        PyErr_SetString(PyExc_TypeError,
            "Py_BuildValue failure");
        return -1;
    }

    PyObject *tupleArgs = PyTuple_New(0); //Return value: New reference.

    Py_INCREF(clash_context);
    Py_INCREF(shortcut_fn);
    result = PyObject_Call(shortcut_fn, tupleArgs, args); //Return value: New reference.
    Py_DECREF(shortcut_fn);
    Py_DECREF(clash_context);
    Py_DECREF(tupleArgs);
    Py_DECREF(args);

    if (result == NULL) {
        return -1;
    }

    if (!PyBool_Check(result)) {
        Py_DECREF(result);
        PyErr_SetString(PyExc_TypeError,
            "script shortcut return value must be as boolean");
        return -1;
    }

    int rs = (result == Py_True) ? 1 : 0;

    Py_DECREF(result);

    return rs;
}

void finalize_Python() {
    Py_CLEAR(main_fn);
    Py_CLEAR(clash_context);
    Py_CLEAR(clash_module);
    Py_FinalizeEx();

//    clash_module = NULL;
//    main_fn = NULL;
//    clash_context = NULL;
}

/* --------------------------------------------------------------------- */