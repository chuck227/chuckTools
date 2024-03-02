#include "winstd.h"
#include <Psapi.h>

static PyObject *ProcNotFoundError, *VirtualAllocFailedError;

static PyObject* 
procinj_injectIntoProcessByName(PyObject *self, PyObject *args);

static PyMethodDef projMeths[] = {
    {"injectIntoProcessByName", procinj_injectIntoProcessByName, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static PyModuleDef procinject = {
    PyModuleDef_HEAD_INIT,
    "processInjection",
    NULL,
    -1,
    projMeths
};

PyMODINIT_FUNC PyInit_processInjection(void){
    PyObject *module = PyModule_Create(&procinject);
    if (NULL == module) return NULL;
    
    return module;
}