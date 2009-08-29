"""  This is an implementation of a resolver based around tdb - the trivial database.
"""
from ctypes import *
import ctypes.util
import pdb, sys
import struct
from aff4_attributes import *

from os import O_RDWR, O_CREAT

try:
    libtdb = CDLL("libtdb.so")
    if not libtdb._name: raise OSError()
except OSError:
    raise ImportError("libtdb not found")

class tdb_data(Structure):
    _fields_ = [ ("data", c_char_p),
                 ("size", c_int)]


libc = CDLL(ctypes.util.find_library("c"))
libtdb.tdb_fetch.restype = tdb_data
libtdb.tdb_nextkey.restype = tdb_data
libtdb.tdb_firstkey.restype = tdb_data

class Tdb:
    """ A Class that obtains access to a tdb database file """
    def __init__(self, filename, hash_size = 64*1024):
        self.filename = filename
        self.tdb_fh = libtdb.tdb_open(filename,
                                      hash_size,
                                      0, O_RDWR | O_CREAT, 0644)
    def store(self, key, value):
        libtdb.tdb_store(self.tdb_fh, tdb_data(key, len(key)), tdb_data(value, len(value)))

    def delete(self, key):
        libtdb.tdb_delete(self.tdb_fh, tdb_data(key, len(key)))

    def get(self, key):
        result = libtdb.tdb_fetch(self.tdb_fh, tdb_data(key, len(key)))
        if not result.data: return None
        
        data_result = result.data[:result.size]
        libc.free(result)

        return data_result

    def list_keys(self):
        current_key = libtdb.tdb_firstkey(self.tdb_fh)
        while current_key:
            if current_key.data:
                yield current_key.data[:current_key.size]
            else:
                break
            
            next_key= libtdb.tdb_nextkey(self.tdb_fh, current_key)
            libc.free(current_key)
            current_key = next_key
            
    ## Make sure we close the files
#    def __del__(self):
#        libtdb.close(self.tdb_fh)

import aff4
NoneObject = aff4.NoneObject

class TDBResolver(aff4.Resolver):
    """ A resolver based on TDB """
    def __init__(self):
        self.read_cache = aff4.Store(50)
        self.write_cache = aff4.Store(50)
        self.clear_hooks()

        ## urn -> urn_id, and urn_id -> urn
        self.urn_db = Tdb("urn.tdb")

        ## attribute -> attribute_id and attribute_id -> attribute
        self.attribute_db = Tdb("attribute.tdb")

        ## urn_id:attribute_id -> data_offset
        self.data_db = Tdb("data.tdb")
        
        ## data is actually stored in a stand alone file
        self.data_store = open("data_store.tdb", "ab+", 0)

    def resolve_id(self, urn):
        return self.get_id(self.urn_db, urn)

    def lock(self, uri, mode='r'):
        ## Not implemented
        pass

    def unlock(self, uri):
        pass

    def export(self, uri, prefix=''):
        """ Export all the properties of uri """
        result = ''
        try:
            urn_id = self.get_id(self.urn_db, uri)
        except ValueError: return ''
        
        for attr in self.attribute_db.list_keys():
            values = self.resolve_list(uri, attr)
            for v in values:
                result += "%s%s=%s\n" % (prefix,attr, v)

        return result

    def export_all(self):
        result = ''
        for urn in self.urn_db.list_keys():
            data = self.export(urn)
            if data:
                result += "\n************** %s **********\n%s" % (urn, data)

        return result

    def max_urn_id(self):
        maximum_id = self.urn_db.get("MAX") or 0
        return int(maximum_id)

    def get_urn_by_id(self, id):
        return self.urn_db.get("%s" % id)

    def get_id(self, tdb, attribute):
        """ Given an attribute returns its ID """
        id = tdb.get(attribute)
        if not id:
            maximum_id = int(tdb.get("MAX") or 0)
            id = maximum_id = "%d" % (maximum_id + 1)
            tdb.store("MAX", maximum_id)
            tdb.store(attribute, maximum_id)
            tdb.store(maximum_id, attribute)
        
        return int(id)

    def calculate_key(self, uri, attribute):
        attribute_id = self.get_id(self.attribute_db, attribute)
        urn_id = self.get_id(self.urn_db, uri)

        return "%d:%d" % (attribute_id, urn_id)


    def set_inheritence(self, child, parent):
        """ Set the inheritence from a child to a parent. Children will
        inherit all attributes of their parents.
        """
        self.set(child.urn, AFF4_INHERIT, parent.urn)
        
    def set(self, uri, attribute, value):
        key = self.calculate_key(uri, attribute)
        value = "%s" % value

        ## This is the place at the end of the file where we put the
        ## new data:
        self.data_store.seek(0,2)
        end_offset = self.data_store.tell()

        ## Struct written is offset to the next element, length
        self.data_store.write(struct.pack("<ll", -1, len(value)))
        self.data_store.write(value)
        
        ## Store the new offset in the db
        self.data_db.store(key, "%d" % end_offset)

        ## Notify all interested parties
        for cb in self.set_hooks:
            cb(uri, attribute, value)
    
    def add(self, uri, attribute, value):
        key = self.calculate_key(uri, attribute)
        
        ## This is the place at the end of the file where we put the
        ## new data:
        self.data_store.seek(0,2)
        end_offset = self.data_store.tell()

        ## Find out where the existing list starts
        next_offset = self.data_db.get(key) or -1
        
        ## Struct written is offset to the next element, length
        self.data_store.write(struct.pack("<ll", int(next_offset),
                                          len(value)))
        self.data_store.write(value)
        
        ## Store the new offset in the db
        self.data_db.store(key, "%d" % end_offset)

        ## Notify all interested parties
        for cb in self.add_hooks:
            cb(uri, attribute, value)

    def resolve(self, uri, attribute):
        """ Return a single (most recently set attribute) """
        key = self.calculate_key(uri, attribute)
        
        offset = self.data_db.get(key)
        if not offset:
            return NoneObject("No attribute %s found on %s" % (attribute, uri))

        self.data_store.seek(int(offset))
        offset, length = struct.unpack("<ll", self.data_store.read(8))
        return self.data_store.read(length)

    def delete(self, uri, attribute):
        key = self.calculate_key(uri, attribute)
        self.data_db.delete(key)

    def resolve_list(self, uri, attribute):
        try:
            key = self.calculate_key(uri, attribute)
        except ValueError:
            return []
        
        offset = self.data_db.get(key)
        if not offset:
            return []
        
        results = []

        while 1:
            self.data_store.seek(int(offset))
            offset, length = struct.unpack("<ll", self.data_store.read(8))
            results.append(self.data_store.read(length))

            if offset==-1: break

        return results

NoneObject = aff4.NoneObject

if __name__=="__main__":
    oracle = TDBResolver()
    oracle.add("hello","cruel","world")
    oracle.add("hello","cruel","world2")
    oracle.add("hello","cruel","world3")
    print oracle.resolve_list("hello","cruel")
