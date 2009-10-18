/** This is the python interface to the tdb trivial database */

#include <Python.h>
#include <stdlib.h>
#include <fcntl.h>
#include <tdb.h>
#include <raptor.h>
#include <unistd.h>
#include <sys/types.h>

#undef min
#define min(X, Y)  ((X) < (Y) ? (X) : (Y))
#undef max
#define max(X, Y)  ((X) > (Y) ? (X) : (Y))

#define BUFF_SIZE 1024
#define SERIALIZER_BUFF_SIZE 102400
#define MAX_KEY "__MAX"
#define VOLATILE_NS "aff4volatile:"

/** Some constants */
static TDB_DATA INHERIT = {
  .dptr = (unsigned char *)"aff4:inherit",
  .dsize = 12
};

static TDB_DATA WLOCK = {
  .dptr = (unsigned char *)"__WLOCK",
  .dsize = 7
};

static TDB_DATA RLOCK = {
  .dptr = (unsigned char *)"__RLOCK",
  .dsize = 7
};

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
    result = PyString_FromStringAndSize((char *)value.dptr, value.dsize);
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
    tmp = PyString_FromStringAndSize((char *)first.dptr, first.dsize);
    if(!tmp) return NULL;

    PyList_Append(result, tmp);
    Py_DECREF(tmp);
    
    next = tdb_nextkey(self->context, first);
    free(first.dptr);
    first = next;
  };
  
  return result;
}


static PyObject *pytdb_lock(PyTDB *self, PyObject *args, PyObject *kwds) {
  tdb_lockall(self->context);
  Py_RETURN_NONE;
}

static PyObject *pytdb_unlock(PyTDB *self, PyObject *args, PyObject *kwds) {
  tdb_unlockall(self->context);
  Py_RETURN_NONE;
}


static int pytdb_dealloc(PyTDB *self) {
  if(self->context)
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
    {"lock", (PyCFunction)pytdb_lock, METH_VARARGS|METH_KEYWORDS,
     "Lock the tdb" },
    {"unlock", (PyCFunction)pytdb_unlock, METH_VARARGS|METH_KEYWORDS,
     "Unlocks the tdb" },

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

typedef struct {
  PyObject_HEAD
  struct tdb_context *urn_db;
  struct tdb_context *attribute_db;
  struct tdb_context *data_db;
  int data_store_fd;
  uint32_t hashsize;
} BaseTDBResolver;

static int resolve(BaseTDBResolver *self, TDB_DATA urn, TDB_DATA attribute, TDB_DATA *value);

static int tdbresolver_dealloc(BaseTDBResolver *self) {
  tdb_close(self->urn_db);
  tdb_close(self->attribute_db);
  tdb_close(self->data_db);
  close(self->data_store_fd);

  return 1;
};

typedef struct TDB_DATA_LIST {
  uint32_t offset;
  uint32_t length;
} TDB_DATA_LIST;

/* Given an int serialise into the buffer */
static int from_int(uint32_t i, char *buff, int buff_len) {
  return snprintf(buff, buff_len, "__%d", i);
};

/** Given a buffer unserialise an int from it */
static uint32_t to_int(TDB_DATA string) {
  unsigned char buff[BUFF_SIZE];
  int buff_len = min(string.dsize, BUFF_SIZE-1);

  if(buff_len < 2) return 0;

  memcpy(buff, string.dptr, buff_len);

  //Make sure its null terminated
  buff[buff_len]=0;

  return strtol((char *)buff+2, NULL, 0);
};

static int tdbresolver_init(BaseTDBResolver *self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"path", "hashsize", NULL};
  char buff[BUFF_SIZE];
  char *path = ".";
  int flags = O_RDWR | O_CREAT;

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "|sL", kwlist, 
				  &path, &self->hashsize))
    return -1;

  if(snprintf(buff, BUFF_SIZE, "%s/urn.tdb", path) >= BUFF_SIZE)
    goto error;
  
  self->urn_db = tdb_open(buff, self->hashsize,
			  0,
			  O_RDWR | O_CREAT, 0644);
  if(!self->urn_db) 
    goto error;

  if(snprintf(buff, BUFF_SIZE, "%s/attribute.tdb", path) >= BUFF_SIZE)
    goto error1;

  self->attribute_db = tdb_open(buff, self->hashsize,
				0,
				O_RDWR | O_CREAT, 0644);

  if(!self->attribute_db) 
    goto error1;

  if(snprintf(buff, BUFF_SIZE, "%s/data.tdb", path) >= BUFF_SIZE)
    goto error2;

  self->data_db = tdb_open(buff, self->hashsize,
			   0,
			   O_RDWR | O_CREAT, 0644);
  
  if(!self->data_db)
    goto error2;

  if(snprintf(buff, BUFF_SIZE, "%s/data_store.tdb", path) >= BUFF_SIZE)
    goto error3;

  self->data_store_fd = open(buff, O_RDWR | O_CREAT, 0644);
  if(self->data_store_fd < 0)
    goto error3;

  // This ensures that the data store never has an offset of 0 (This
  // indicates an error)
  // Access to the tdb_store is managed via locks on the data.tdb
  tdb_lockall(self->data_db);
  if(lseek(self->data_store_fd, 0, SEEK_END)==0) {
    (void)write(self->data_store_fd, "data",4);
  };
  tdb_unlockall(self->data_db);

  return 0;

 error3:
  tdb_close(self->data_db);
 error2:
  tdb_close(self->attribute_db);
 error1:
  tdb_close(self->urn_db);
 error:
  PyErr_Format(PyExc_IOError, "Unable to open tdb files");

  return -1;
};

static PyObject *get_urn_by_id(BaseTDBResolver *self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"id", NULL};
  char buff[BUFF_SIZE];
  uint32_t id;
  PyObject *result, *id_obj;
  TDB_DATA urn;
  TDB_DATA key;

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, 
				  &id_obj))
    return NULL;

  id_obj = PyNumber_Long(id_obj);
  if(!id_obj) return NULL;

  id = PyLong_AsUnsignedLongLong(id_obj);
  Py_DECREF(id_obj);

  /* We get given an ID and we retrieve the URN it belongs to */
  key.dptr = (unsigned char *)buff;
  key.dsize = from_int(id, buff, BUFF_SIZE);

  urn = tdb_fetch(self->urn_db, key);

  if(urn.dptr) {
    result = PyString_FromStringAndSize((char *)urn.dptr, urn.dsize);
    free(urn.dptr);
    return result;
  };

  Py_RETURN_NONE;
};

/** Fetches the id for the given key from the database tdb - if
    create_new is set and there is no id present, we create a new id
    and return id.
*/
static uint32_t get_id(struct tdb_context *tdb, TDB_DATA key, int create_new) {
  char buff[BUFF_SIZE];
  TDB_DATA urn_id;
  uint32_t max_id=0;
  uint32_t result=0;
  
  /* We get given an ID and we retrieve the URN it belongs to */
  tdb_lockall(tdb);
  urn_id = tdb_fetch(tdb, key);

  if(urn_id.dptr) {
    result = to_int(urn_id);
    free(urn_id.dptr);

    tdb_unlockall(tdb);
    return result;
  } else if(create_new) {
    TDB_DATA max_key;

    max_key.dptr = (unsigned char *)MAX_KEY;
    max_key.dsize = strlen(MAX_KEY);

    urn_id = tdb_fetch(tdb, max_key);
    if(urn_id.dptr) {
      max_id = to_int(urn_id);
      free(urn_id.dptr);
    };

    max_id++;
    
    // Update the new MAX_KEY
    urn_id.dptr = (unsigned char *)buff;
    urn_id.dsize = from_int(max_id, buff, BUFF_SIZE);
    tdb_store(tdb, key, urn_id, TDB_REPLACE);
    tdb_store(tdb, max_key, urn_id, TDB_REPLACE);
    tdb_store(tdb, urn_id, key, TDB_REPLACE);

    tdb_unlockall(tdb);
    return max_id;
  };

  tdb_unlockall(tdb);
  // This should never happen
  return 0;
};


static PyObject *get_id_by_urn(BaseTDBResolver *self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"urn", "create_new", NULL};
  TDB_DATA key;
  int create_new=0;
  
  if(!PyArg_ParseTupleAndKeywords(args, kwds, "s#|L", kwlist, 
				  &key.dptr, &key.dsize, &create_new))
    return NULL;

  return PyLong_FromUnsignedLongLong(get_id(self->urn_db, key, create_new));
};

/** Writes the data key onto the buffer - this is a combination of the
    uri_id and the attribute_id 
*/
static int calculate_key(BaseTDBResolver *self, TDB_DATA uri, 
			 TDB_DATA attribute, char *buff,
			 int buff_len, int create_new) {
  uint32_t urn_id = get_id(self->urn_db, uri, create_new);
  uint32_t attribute_id = get_id(self->attribute_db, attribute, create_new);

  // urn or attribute not found
  if(urn_id == 0 || attribute_id == 0) return 0;

  return snprintf(buff, buff_len, "%d:%d", urn_id, attribute_id);
};

/** returns the list head in the data file for the uri and attribute
    specified. Return 1 if found, 0 if not found. 
*/
static uint32_t get_data_head(BaseTDBResolver *self, TDB_DATA uri, TDB_DATA attribute, 
			 TDB_DATA_LIST *result) {
  char buff[BUFF_SIZE];
  TDB_DATA data_key;

  data_key.dptr = (unsigned char *)buff;
  data_key.dsize = calculate_key(self, uri, attribute, buff, BUFF_SIZE, 0);

  if(data_key.dsize > 0) {
    // We found these attribute/urn
    TDB_DATA offset_serialised = tdb_fetch(self->data_db, data_key);
    if(offset_serialised.dptr) {
      // We found the head - read the struct
      uint32_t offset = to_int(offset_serialised);
      lseek(self->data_store_fd, offset, SEEK_SET);
      if(read(self->data_store_fd, result, sizeof(*result)) == sizeof(*result)) {
	return offset;
      };
      
      free(offset_serialised.dptr);
    };
  };

  return 0;
};

static inline int get_data_next(BaseTDBResolver *self, TDB_DATA_LIST *i){
  if(i->offset > 0) {
    lseek(self->data_store_fd, i->offset, SEEK_SET);
    if(read(self->data_store_fd, i, sizeof(*i)) == sizeof(*i)) {
      return 1;
    };
  };

  return 0;
};

// check if the value is already set for urn and attribute - honors inheritance
static int is_value_present(BaseTDBResolver *self,TDB_DATA urn, TDB_DATA attribute,
			    TDB_DATA value, int follow_inheritence) {
  TDB_DATA_LIST i;
  char buff[BUFF_SIZE];
  TDB_DATA tmp;

  while(1) {

    // Check the current urn,attribute set
    if(get_data_head(self, urn, attribute, &i)) {
      do {
	if(value.dsize == i.length && i.length < 100000) {
	  char buff[value.dsize];
	  
	  // Read this much from the file
	  if(read(self->data_store_fd, buff, i.length) < i.length) {
	    return 0;
	  };
	  
	  if(!memcmp(buff, value.dptr, value.dsize)) {
	    // Found it:
	    return 1;
	  };
	};
      } while(get_data_next(self, &i));
    };

    if(!follow_inheritence) break;

    // Follow inheritence
    tmp.dptr = (unsigned char *)buff;
    tmp.dsize = BUFF_SIZE;
    // Substitute our urn with a possible inherited URN
    if(resolve(self, urn, INHERIT, &tmp)) { // Found - put in urn
      // Copy the urn
      urn.dptr = (unsigned char *)buff;
      urn.dsize = tmp.dsize;
    } else {
      break;
    };

    // Do it all again with the inherited URN
  };
    
  return 0;
};

static PyObject *add(BaseTDBResolver *self, PyObject *args, PyObject *kwds) {
  char buff[BUFF_SIZE];
  char buff2[BUFF_SIZE];
  static char *kwlist[] = {"urn", "attribute", "value", "unique", NULL};
  TDB_DATA urn;
  TDB_DATA attribute;
  TDB_DATA key;
  PyObject *value_obj, *value_str;
  TDB_DATA value;
  TDB_DATA offset;
  TDB_DATA_LIST i;
  uint32_t previous_offset=0;
  uint32_t new_offset;
  int unique = 0;

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "s#s#O|L", kwlist, 
				  &urn.dptr, &urn.dsize, 
				  &attribute.dptr, &attribute.dsize,
				  &value_obj, &unique))
    return NULL;

  // Convert the object to a string
  value_str = PyObject_Str(value_obj);
  if(!value_str) return NULL;

  PyString_AsStringAndSize(value_str, (char **)&value.dptr, 
			   (int *)&value.dsize);

  /** If the value is already in the list, we just ignore this
      request.
  */
  if(unique && is_value_present(self, urn, attribute, value, 1)) {
    goto exit;
  };

  // Ok if we get here, the value is not already stored there.
  key.dptr = (unsigned char *)buff;
  key.dsize = calculate_key(self, urn, attribute, buff, BUFF_SIZE, 1);

  // Lock the data_db to synchronise access to the store:
  tdb_lockall(self->data_db);

  offset = tdb_fetch(self->data_db, key);
  if(offset.dptr) {
    previous_offset = to_int(offset);
    free(offset.dptr);
  };

  // Go to the end and write the new record
  new_offset = lseek(self->data_store_fd, 0, SEEK_END);
  i.offset = previous_offset;
  i.length = value.dsize;

  write(self->data_store_fd, &i, sizeof(i));
  write(self->data_store_fd, value.dptr, value.dsize);

  // Now store the offset to this in the tdb database
  value.dptr = (unsigned char *)buff2;
  value.dsize = from_int(new_offset, buff2, BUFF_SIZE);

  tdb_store(self->data_db, key, value, TDB_REPLACE);

  // Done
  tdb_unlockall(self->data_db);

  exit:
  Py_DECREF(value_str);
  Py_RETURN_NONE;
};

static int set_new_value(BaseTDBResolver *self, TDB_DATA urn, TDB_DATA attribute, 
			 TDB_DATA value) {
  TDB_DATA key,offset;
  char buff[BUFF_SIZE];
  char buff2[BUFF_SIZE];
  uint32_t new_offset;
  TDB_DATA_LIST i;

  // Update the value in the db and replace with new value
  key.dptr = (unsigned char *)buff;
  key.dsize = calculate_key(self, urn, attribute, buff, BUFF_SIZE, 1);

  // Lock the database
  tdb_lockall(self->data_db);

  // Go to the end and write the new record
  new_offset = lseek(self->data_store_fd, 0, SEEK_END);
  // The offset to the next item in the list
  i.offset = 0;
  i.length = value.dsize;

  write(self->data_store_fd, &i, sizeof(i));
  write(self->data_store_fd, value.dptr, value.dsize);

  offset.dptr = (unsigned char *)buff2;
  offset.dsize = from_int(new_offset, buff2, BUFF_SIZE);

  tdb_store(self->data_db, key, offset, TDB_REPLACE);

  //Done
  tdb_unlockall(self->data_db);

  return 1;
};

static PyObject *set(BaseTDBResolver *self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"urn", "attribute", "value", NULL};
  TDB_DATA urn;
  TDB_DATA attribute;
  PyObject *value_obj, *value_str;
  TDB_DATA value;

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "s#s#O", kwlist, 
				  &urn.dptr, &urn.dsize, 
				  &attribute.dptr, &attribute.dsize,
				  &value_obj))
    return NULL;

  // Convert the object to a string
  value_str = PyObject_Str(value_obj);
  if(!value_str) return NULL;

  PyString_AsStringAndSize(value_str, (char **)&value.dptr, (int *)&value.dsize);

  /** If the value is already in the list, we just ignore this
      request.
  */
  if(is_value_present(self, urn, attribute, value, 1)) {
    goto exit;
  };

  set_new_value(self, urn, attribute, value);

 exit:
  Py_DECREF(value_str);
  Py_RETURN_NONE;
};

static PyObject *delete(BaseTDBResolver *self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"urn", "attribute", NULL};
  TDB_DATA urn;
  TDB_DATA attribute;
  TDB_DATA key;
  char buff[BUFF_SIZE];

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "s#s#", kwlist, 
				  &urn.dptr, &urn.dsize, 
				  &attribute.dptr, &attribute.dsize
				  ))
    return NULL;

  key.dptr = (unsigned char *)buff;
  key.dsize = calculate_key(self, urn, attribute, buff, BUFF_SIZE, 0);

  // Remove the key from the database
  tdb_delete(self->data_db, key);

  Py_RETURN_NONE;
};

/** Resolves a single attribute and fills into value. Value needs to
    be initialised with a valid dptr and dsize will indicate the
    buffer size
*/
static int resolve(BaseTDBResolver *self, TDB_DATA urn, TDB_DATA attribute, TDB_DATA *value) {
  TDB_DATA_LIST i;
  
  if(get_data_head(self, urn, attribute, &i)) {
    int length = min(value->dsize, i.length);
    
    // Read this much from the file
    if(read(self->data_store_fd, value->dptr, length) < length) {
      // Oops cant read enough
      goto error;
    };

    value->dsize= length;
    return 1;
  };

 error:
  value->dsize = 0;

  return 0;
};


/** Given a head in the data store, construct a python list with all
    the values and return it.
*/
static PyObject *retrieve_attribute_list(BaseTDBResolver *self, TDB_DATA_LIST *head) {
  PyObject *result = PyList_New(0);

  do {
    PyObject *tmp = PyString_FromStringAndSize(NULL, head->length);
    char *buff;
    
    if(!tmp) return NULL;
    
    buff = PyString_AsString(tmp);
    // Read this much from the file
    if(read(self->data_store_fd, buff, head->length) < head->length) {
      // Oops cant read enough
      Py_DECREF(tmp);
      goto exit;
    };
    
    // Add the data to the list
    PyList_Append(result, tmp);
    Py_DECREF(tmp);
  } while(get_data_next(self, head));

 exit:
  return result;
};

static PyObject *resolve_list(BaseTDBResolver *self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"urn", "attribute", "follow_inheritence", NULL};
  TDB_DATA urn,tmp;
  char buff[BUFF_SIZE];
  TDB_DATA attribute;
  TDB_DATA_LIST i;
  int follow_inheritence=1;

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "s#s#|L", kwlist, 
				  &urn.dptr, &urn.dsize, 
				  &attribute.dptr, &attribute.dsize,
				  &follow_inheritence))
    return NULL;

  tmp.dptr = (unsigned char *)buff;

  while(1) {
    if(get_data_head(self, urn, attribute, &i) && i.length < 100000) {
      return retrieve_attribute_list(self, &i);
    };
    
    if(!follow_inheritence) break;
    
    tmp.dsize = BUFF_SIZE;
    // Substitute our urn with a possible inherited URN
    if(resolve(self, urn, INHERIT, &tmp)) { // Found - put in urn
      // Copy the urn
      urn.dptr = (unsigned char *)buff;
      urn.dsize = tmp.dsize;
    } else {
      break;
    };
  };
  
  return PyList_New(0);
};

static PyObject *export_all_urns(BaseTDBResolver *self, PyObject *args, PyObject *kwds) {
  PyObject *result = PyList_New(0);
  TDB_DATA first = tdb_firstkey(self->urn_db);
  TDB_DATA next;
  PyObject *tmp;

  while(first.dptr) {
    // Ignore keys which start with _ - they are hidden
    if(*first.dptr != '_') {
      tmp = PyString_FromStringAndSize((char *)first.dptr, first.dsize);
      if(!tmp) return NULL;

      PyList_Append(result, tmp);
      Py_DECREF(tmp);
    };
    
    next = tdb_nextkey(self->urn_db, first);
    free(first.dptr);
    first = next;
  };
  
  return result;
};


static PyObject *export_dict(BaseTDBResolver *self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"urn", NULL};
  TDB_DATA urn;
  TDB_DATA attribute, next;
  TDB_DATA_LIST data_list;
  PyObject *result;

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "s#", kwlist, 
				  &urn.dptr, &urn.dsize))
    return NULL;
  
  result = PyDict_New();
  if(!result) return NULL;

  // Iterate over all the attribute and check if they are set
  attribute = tdb_firstkey(self->attribute_db);
  while(attribute.dptr) {

    // See if we have this attribute set
    if(get_data_head(self, urn, attribute, &data_list)) {
      PyObject *list = retrieve_attribute_list(self, &data_list);
      PyObject *key = PyString_FromStringAndSize((char *)attribute.dptr, attribute.dsize);

      PyDict_SetItem(result, key, list);
      Py_DECREF(list);
      Py_DECREF(key);
    };

    next = tdb_nextkey(self->attribute_db, attribute);
    free(attribute.dptr);
    attribute = next;
  };

  return result;
};

static PyObject *lock(BaseTDBResolver *self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"urn", "mode", NULL};
  char *mode;
  TDB_DATA urn;
  TDB_DATA attribute;
  TDB_DATA_LIST data_list;
  uint32_t offset;

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "s#s", kwlist, 
				  &urn.dptr, &urn.dsize, &mode))
    return NULL;

  if(*mode == 'r') attribute = RLOCK;
  else if(*mode == 'w') attribute = WLOCK;
  else return PyErr_Format(PyExc_IOError, "Invalid mode %c", *mode);

  offset = get_data_head(self, urn, attribute, &data_list);
  if(!offset){
    // The attribute is not set - make it now:
    set_new_value(self,urn, attribute, attribute);
    offset = get_data_head(self, urn, attribute, &data_list);
    if(!offset) {
      return PyErr_Format(PyExc_IOError, "Unable to set lock attribute");
    };
  };

  // If we get here data_list should be valid:
  lseek(self->data_store_fd, offset, SEEK_SET);
  /*
    printf("locking %s %lu:%u\n", urn.dptr, offset, data_list.length);
    fflush(stdout);
  */
  if(lockf(self->data_store_fd, F_LOCK, data_list.length)==-1){
    return PyErr_Format(PyExc_IOError, "Unable to lock: %s", strerror(errno));
  };

  Py_RETURN_NONE;
}

static PyObject *release(BaseTDBResolver *self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"urn", "mode", NULL};
  char *mode;
  TDB_DATA urn;
  TDB_DATA attribute;
  TDB_DATA_LIST data_list;
  uint32_t offset;

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "s#s", kwlist, 
				  &urn.dptr, &urn.dsize, &mode))
    return NULL;

  if(*mode == 'r') attribute = RLOCK;
  else if(*mode == 'w') attribute = WLOCK;
  else return PyErr_Format(PyExc_IOError, "Invalid mode %c", *mode);

  offset = get_data_head(self, urn, attribute, &data_list);
  if(!offset) {
    goto exit;
    return PyErr_Format(PyExc_IOError, "URN does not appear to be locked?");
  };

  // If we get here data_list should be valid - just unlock the byte range
  lseek(self->data_store_fd, offset, SEEK_SET);
  while(1) {
    int i = lockf(self->data_store_fd, F_ULOCK, data_list.length);
    if(i==-1)
      return PyErr_Format(PyExc_IOError, "Unable to unlock: %s", strerror(errno));
    if(i==0) break;
  };

  /*
    printf("unlocking %s\n", urn.dptr);
    fflush(stdout);
  */
 exit:
  Py_RETURN_NONE;
}

static PyMethodDef PyTDBResolver_methods[] = {
  {"get_urn_by_id",(PyCFunction)get_urn_by_id, METH_VARARGS|METH_KEYWORDS,
   "Resolves a URN by an id"},
  {"get_id_by_urn",(PyCFunction)get_id_by_urn, METH_VARARGS|METH_KEYWORDS,
   "Resolves a unique ID for a urn"},
  {"set",(PyCFunction)set, METH_VARARGS|METH_KEYWORDS,
   "Sets a attribute for a given URN"},
  {"add",(PyCFunction)add, METH_VARARGS|METH_KEYWORDS,
   "Adds an attribute for a URN"},
  {"delete",(PyCFunction)delete, METH_VARARGS|METH_KEYWORDS,
   "deletes all attributes for a URN"},
  {"resolve_list",(PyCFunction)resolve_list, METH_VARARGS|METH_KEYWORDS,
   "Returns a list of attribute values for a URN"},
  {"export_dict", (PyCFunction)export_dict, METH_VARARGS|METH_KEYWORDS,
   "return all the attributes of the given URN"},
  {"export_all_urns", (PyCFunction)export_all_urns, METH_VARARGS|METH_KEYWORDS,
   "return all the urns in the tdb resolver"},
  {"lock", (PyCFunction)lock, METH_VARARGS|METH_KEYWORDS,
   "locks a given URN - all other lock requests will block until this thread unlocks it. There are 2 types of lock held by each URN a 'r' and 'w' lock."},
  {"release", (PyCFunction)release, METH_VARARGS|METH_KEYWORDS,
   "release 'r' or 'w' locks of the given URN"},
  {NULL}  /* Sentinel */
};

static PyTypeObject PyTDBResolver_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                         /* ob_size */
    "pytdb.BaseTDBResolver",               /* tp_name */
    sizeof(BaseTDBResolver),            /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)tdbresolver_dealloc,/* tp_dealloc */
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
    "TDB Resolver object",     /* tp_doc */
    0,	                       /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    PyTDBResolver_methods,            /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)tdbresolver_init,      /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};

static PyMethodDef tdb_methods[] = {
  {NULL}  /* Sentinel */
};

/***** Following is an implementation of a serialiser */
typedef struct {
  PyObject_HEAD
  raptor_serializer *rdf_serializer;
  raptor_iostream *iostream;
  BaseTDBResolver *resolver;
  PyObject *callback;
  PyObject *data;

  // We buffer the data through here to minimize expensive python
  // calls:
  char buffer[SERIALIZER_BUFF_SIZE];
  int size;
} RDFSerializer;

static int rdfserializer_dealloc(RDFSerializer *self) {
  Py_DECREF(self->callback);
  Py_DECREF(self->data);
  Py_DECREF(self->resolver);
  raptor_free_serializer(self->rdf_serializer);

  return 1;
};

/** Flush the buffer to the python callback */
static void flush(void *context) {
  RDFSerializer *self=context;
  PyObject *result;

  if(self->size > 0) {
    result = PyObject_CallFunction(self->callback, "Os#", self->data, 
				   self->buffer, self->size);
    if(result) {
      Py_DECREF(result);
    };
    // Swallow the data
    self->size = 0;
  };
};

static int iostream_write_byte(void *context, const int byte) {
  RDFSerializer *self=context;

  if(self->size + 1 >= SERIALIZER_BUFF_SIZE) {
    flush(self);
  };

  self->buffer[self->size] = byte;
  self->size++;
  
  return 1;
};

static int iostream_write_bytes(void *context, const void *ptr, size_t size, size_t nmemb) {
  RDFSerializer *self=context;
  int length = nmemb * size;

  if(self->size + length >= SERIALIZER_BUFF_SIZE) {
    flush(self);
  };

  memcpy(self->buffer+self->size, ptr, length);
  self->size += length;

  return length;
}

raptor_iostream_handler2 python_iostream_handler = {
  .version = 2,
  .write_byte = iostream_write_byte,
  .write_bytes = iostream_write_bytes,
  .finish = flush,
  .write_end = flush
};

static int rdfserializer_init(RDFSerializer *self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"resolver", "write_callback", "data", "base", "type", NULL};
  char *type = "turtle";
  char *base = "";

  self->iostream = raptor_new_iostream_from_handler2((void *)self, &python_iostream_handler);

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "OO|Oss", kwlist, 
				  &self->resolver, 
				  &self->callback,
				  &self->data, 
				  &base,
				  &type))
    goto error;

  if(!PyCallable_Check(self->callback)) {
    PyErr_Format(PyExc_RuntimeError, "Write callback is not callable?");
    goto error;
  };

  // Try to make a new serialiser
  self->rdf_serializer = raptor_new_serializer(type);
  if(!self->rdf_serializer) {
    PyErr_Format(PyExc_RuntimeError, "Cant create serializer of type %s", type);
    goto error;
  };

  {
    raptor_uri uri = raptor_new_uri((const unsigned char*)base);
    raptor_serialize_start(self->rdf_serializer, 
			   uri, self->iostream);
  };

  Py_INCREF(self->callback);
  Py_INCREF(self->resolver);
  if(self->data)
    Py_INCREF(self->data);

  return 0;

 error:
  return -1;
};

/** Given an offet in the data_store export the entire list through
    the serializer.
*/
static void export_list(RDFSerializer *self, TDB_DATA urn, 
			TDB_DATA attribute, TDB_DATA offset) {
  // Get the offset to the value and retrieve it from the data
  // store:
  TDB_DATA_LIST tmp;

  tmp.offset = to_int(offset);
  
  // Iterate over all hits in the attribute list
  while(tmp.offset) {
    lseek(self->resolver->data_store_fd, tmp.offset, SEEK_SET);
    if(read(self->resolver->data_store_fd, &tmp, sizeof(tmp))==sizeof(tmp) && 
       tmp.length < 10000) {
      char buff[tmp.length];

      buff[tmp.length]=0;
      read(self->resolver->data_store_fd, buff, tmp.length);

      // Now export this statement:
      {
	raptor_statement triple;
	char urn_buf[BUFF_SIZE];
	char attribute_buf[BUFF_SIZE];
	
	urn.dsize = min(urn.dsize, BUFF_SIZE-1);
	memcpy(urn_buf, urn.dptr, urn.dsize);
	
	attribute.dsize = min(attribute.dsize, BUFF_SIZE-1);
	memcpy(attribute_buf, attribute.dptr, attribute.dsize);
	
	urn_buf[urn.dsize]=0;
	attribute_buf[attribute.dsize]=0;
	
	triple.subject = (void*)raptor_new_uri((const unsigned char*)urn_buf);
	triple.subject_type = RAPTOR_IDENTIFIER_TYPE_RESOURCE;
	
	triple.predicate = (void*)raptor_new_uri((const unsigned char*)attribute_buf);
	triple.predicate_type = RAPTOR_IDENTIFIER_TYPE_RESOURCE;
	
	triple.object = buff;
	triple.object_type = RAPTOR_IDENTIFIER_TYPE_LITERAL;
	triple.object_literal_datatype = 0;
	//triple.object_literal_language=(const unsigned
	//char*)"en";
	triple.object_literal_language=NULL;
	
	raptor_serialize_statement(self->rdf_serializer, &triple);
	raptor_free_uri((raptor_uri*)triple.subject);
	raptor_free_uri((raptor_uri*)triple.predicate);	      
      };
    } else return;
  };
};


static PyObject *rdfserializer_serialize_urn(RDFSerializer *self, 
					     PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"urn", "exclude", NULL};
  TDB_DATA urn,id;
  int max_attr_id=1,i, urn_id;
  PyObject *exclude=NULL;

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "s#|O", kwlist, 
				  &urn.dptr, &urn.dsize, &exclude))
    return NULL;
     
  // Find the URN id
  {
    id = tdb_fetch(self->resolver->urn_db, urn);
    if(!id.dptr)
      return PyErr_Format(PyExc_RuntimeError, "Urn '%s' not found", urn.dptr);
    
    urn_id = to_int(id);
    free(id.dptr);
  };

  //Find the maximum attribute ID
  {
    TDB_DATA max_key;

    max_key.dptr = (unsigned char *)MAX_KEY;
    max_key.dsize = strlen(MAX_KEY);

    id = tdb_fetch(self->resolver->attribute_db, max_key);
    if(id.dptr) {
      max_attr_id = to_int(id);
      free(id.dptr);
    };
  };

  // Now just iterate over all the attribute id's and guess if they
  // are present - this avoids having to allocate memory
  // unnecessarily.
  for(i=1; i<=max_attr_id; i++) {
    TDB_DATA key, offset;
    char buff[BUFF_SIZE];

    // Make up the key to the data table
    key.dptr = (unsigned char*)buff;
    key.dsize = snprintf(buff, BUFF_SIZE, "%d:%d", urn_id, i);
    
    offset = tdb_fetch(self->resolver->data_db, key);
    if(offset.dptr) {
      // Found it
      TDB_DATA attribute;
      char buff[BUFF_SIZE];

      // Resolve the attribute_id back to a named attribute
      attribute.dptr = (unsigned char*)buff;
      attribute.dsize = from_int(i, buff, BUFF_SIZE);

      attribute = tdb_fetch(self->resolver->attribute_db, attribute);
      // Ignore volatile namespace attributes
      if(attribute.dptr && memcmp(attribute.dptr, VOLATILE_NS, 
				  min(strlen(VOLATILE_NS), attribute.dsize))) {
	// Check if the attribute should be ignored
#if 1
	PyObject *string = PyString_FromStringAndSize((char *)attribute.dptr, attribute.dsize);

	if(exclude && !PySequence_Contains(exclude, string)) {
	  export_list(self, urn, attribute, offset);
	};
	Py_DECREF(string);
#else
	export_list(self, urn, attribute, offset);
#endif
	free(attribute.dptr);
      };
      free(offset.dptr);
    };
  };

  Py_RETURN_NONE;
};

static PyObject *rdfserializer_close(RDFSerializer *self, 
				     PyObject *args, PyObject *kwds) {
  raptor_serialize_end(self->rdf_serializer);

  Py_RETURN_NONE;
};

static PyObject *rdfserializer_set_namespace(RDFSerializer *self,
					     PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"urn", "namespace", NULL};
  char *urn;
  unsigned char *namespace;
  raptor_uri *uri;

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "ss", kwlist, 
				  &urn, &namespace))
    return NULL;

  uri = (void*)raptor_new_uri((const unsigned char*)urn);
  if(raptor_serialize_set_namespace(self->rdf_serializer, uri, namespace)) {
    return PyErr_Format(PyExc_RuntimeError, 
			"Unable to set namespace %s for urn %s", namespace, urn);
  };

  Py_RETURN_NONE;
};

static PyMethodDef RDFSerializer_methods[] = {
    {"serialize_urn", (PyCFunction)rdfserializer_serialize_urn, METH_VARARGS|METH_KEYWORDS,
     "serializes all the statements for a given URN" },
    {"close", (PyCFunction)rdfserializer_close, METH_VARARGS | METH_KEYWORDS,
     "closes the serializer and forces any pending output to be flushed"},
    {"set_namespace", (PyCFunction)rdfserializer_set_namespace, METH_VARARGS | METH_KEYWORDS,
     "Adds a new namespace."},
    {NULL}  /* Sentinel */
};

static PyTypeObject RDFSerializer_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                         /* ob_size */
    "pytdb.RDFSerializer",               /* tp_name */
    sizeof(RDFSerializer),            /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)rdfserializer_dealloc,/* tp_dealloc */
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
    "An RDF Serializer",     /* tp_doc */
    0,	                       /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    RDFSerializer_methods,            /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)rdfserializer_init,      /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};


PyMODINIT_FUNC initpytdb(void) {
  /* create module */
  PyObject *m = Py_InitModule3("pytdb", tdb_methods,
			       "PyTDB module.");
  
  /* setup tdbType type */
  tdbType.tp_new = PyType_GenericNew;
  if (PyType_Ready(&tdbType) < 0)
    return;

  Py_INCREF((PyObject *)&tdbType);
  PyModule_AddObject(m, "PyTDB", (PyObject *)&tdbType);

  PyTDBResolver_Type.tp_new = PyType_GenericNew;
  if (PyType_Ready(&PyTDBResolver_Type) < 0)
    return;

  Py_INCREF((PyObject *)&PyTDBResolver_Type);
  PyModule_AddObject(m, "BaseTDBResolver", (PyObject *)&PyTDBResolver_Type);

  RDFSerializer_Type.tp_new = PyType_GenericNew;
  if (PyType_Ready(&RDFSerializer_Type) < 0)
    return;

  Py_INCREF((PyObject *)&RDFSerializer_Type);
  PyModule_AddObject(m, "RDFSerializer", (PyObject *)&RDFSerializer_Type);

  raptor_init();
}
