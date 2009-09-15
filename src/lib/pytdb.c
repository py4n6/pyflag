/** This is the python interface to the tdb trivial database */

#include <Python.h>
#include <stdlib.h>
#include <fcntl.h>
#include <tdb.h>

typedef struct {
  PyObject_HEAD
  struct tdb_context *context;
  char *filename;
  uint32_t hashsize;
} PyTDB;

static int pytdb_init(PyTDB *self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"filename", "hashsize", NULL};

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "s|L", kwlist, 
				  &self->filename, &self->hashsize))
    return -1; 

  self->context = tdb_open(self->filename, self->hashsize,
			   0,
			   O_RDWR | O_CREAT, 0644);

  if(!self->context) {
    PyErr_Format(PyExc_IOError, "Unable to open tdb file: %s", self->filename);
    return -1;
  };

  return 0;
};

static PyObject *pytdb_store(PyTDB *self, PyObject *args, PyObject *kwds) {
  TDB_DATA key;
  TDB_DATA value;
  static char *kwlist[] = {"key", "value", NULL};
  
  if(!PyArg_ParseTupleAndKeywords(args, kwds, "s#s#", kwlist, 
				  &key.dptr, &key.dsize, 
				  &value.dptr, &value.dsize))
    return NULL;
  
  tdb_store(self->context, key, value, TDB_REPLACE);
  
  Py_RETURN_NONE;
}

static PyObject *pytdb_delete(PyTDB *self, PyObject *args, PyObject *kwds) {
  TDB_DATA key;
  static char *kwlist[] = {"key", NULL};
  
  if(!PyArg_ParseTupleAndKeywords(args, kwds, "s#", kwlist, 
				  &key.dptr, &key.dsize))
    return NULL; 
  
  tdb_delete(self->context, key);
  
  Py_RETURN_NONE;
};

static PyObject *pytdb_get(PyTDB *self, PyObject *args, PyObject *kwds) {
  TDB_DATA key;
  TDB_DATA value;
  PyObject *result;

  static char *kwlist[] = {"key", NULL};
  
  if(!PyArg_ParseTupleAndKeywords(args, kwds, "s#", kwlist, 
				  &key.dptr, &key.dsize)) {
    return NULL; 
  };

  // Make a python string of the data  
  value = tdb_fetch(self->context, key);
  if(value.dptr) {
    result = PyString_FromStringAndSize(value.dptr, value.dsize);
    free(value.dptr);
    
    return result;
  };
  
  Py_RETURN_NONE;
};

static PyObject *pytdb_list_keys(PyTDB *self, PyObject *args, PyObject *kwds) {
  PyObject *result = PyList_New(0);
  TDB_DATA first = tdb_firstkey(self->context);
  TDB_DATA next;
  PyObject *tmp;

  while(first.dptr) {
    tmp = PyString_FromStringAndSize(first.dptr, first.dsize);
    if(!tmp) return NULL;

    PyList_Append(result, tmp);
    Py_DECREF(tmp);
    
    next = tdb_nextkey(self->context, first);
    free(first.dptr);
    first = next;
  };
  
  return result;
}

static int pytdb_dealloc(PyTDB *self) {
  tdb_close(self->context);
  return 1;
};

static PyMethodDef PyTDB_methods[] = {
    {"store", (PyCFunction)pytdb_store, METH_VARARGS|METH_KEYWORDS,
     "Store a (key,value)" },
    {"delete", (PyCFunction)pytdb_delete, METH_VARARGS|METH_KEYWORDS,
     "Delete a key" },
    {"get", (PyCFunction)pytdb_get, METH_VARARGS|METH_KEYWORDS,
     "Get a value associated with a key" },
    {"list_keys", (PyCFunction)pytdb_list_keys, METH_VARARGS|METH_KEYWORDS,
     "Return a list of keys" },
    {NULL}  /* Sentinel */
};

static PyTypeObject tdbType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /* ob_size */
    "pytdb.TDB",               /* tp_name */
    sizeof(PyTDB),            /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)pytdb_dealloc,/* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_compare */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,        /* tp_flags */
    "TDB database object",     /* tp_doc */
    0,	                       /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    PyTDB_methods,            /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)pytdb_init,      /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};


static PyMethodDef PyTDBResolver_methods[] = {


};



static PyMethodDef tdb_methods[] = {
  {NULL}  /* Sentinel */
};

PyMODINIT_FUNC initpytdb(void) {
  /* create module */
  PyObject *m = Py_InitModule3("pytdb", tdb_methods,
			       "PyTDB module.");
  
  /* setup tdbType type */
  tdbType.tp_new = PyType_GenericNew;
  if (PyType_Ready(&tdbType) < 0)
    return;

  Py_INCREF(&tdbType);
  PyModule_AddObject(m, "PyTDB", (PyObject *)&tdbType);
}
