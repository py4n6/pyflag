"""  This is an implementation of a resolver based around tdb - the trivial database.

TDB is a simple key value database as used in samba:
http://sourceforge.net/projects/tdb/

In ubuntu you can get it using
apt-get install libtdb1

"""
from ctypes import *
import ctypes.util
import pdb, sys
import struct
from aff4_attributes import *
import RDF

from os import O_RDWR, O_CREAT
MAX_KEY = '__MAX'

try:
    libtdb = CDLL("libtdb.so.1")
    if not libtdb._name: raise OSError()
except OSError:
    raise ImportError("libtdb not found")

class tdb_data(Structure):
    _fields_ = [ ("data", c_char_p),
                 ("size", c_int)]

TDB_DEFAULT= 0  #* just a readability place holder *#
TDB_CLEAR_IF_FIRST= 1
TDB_INTERNAL= 2 #* don't store on disk *#
TDB_NOLOCK =  4 #* don't do any locking *#
TDB_NOMMAP =  8 #* don't use mmap *#
TDB_CONVERT= 16 #* convert endian (internal use) *#
TDB_BIGENDIAN =32 #* header is big-endian (internal use) *#
TDB_NOSYNC =  64 #* don't use synchronous transactions *#
TDB_SEQNUM =  128 #* maintain a sequence number *#
TDB_VOLATILE =  256 #* Activate the per-hashchain freelist, default 5 *#

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
                                      ## This doesnt seem to improve performance at all
                                      #TDB_VOLATILE | TDB_NOSYNC | TDB_NOLOCK,
                                      0,
                                      O_RDWR | O_CREAT, 0644)
    def store(self, key, value):
        libtdb.tdb_store(self.tdb_fh, tdb_data(key, len(key)), tdb_data(value, len(value)))

    def delete(self, key):
        libtdb.tdb_delete(self.tdb_fh, tdb_data(key, len(key)))

    def get(self, key):
        key = "%s" % key
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

    def resolve_urn_from_id(self, id):
        return self.urn_db.get(id)

    def lock(self, uri, mode='r'):
        ## Not implemented
        pass

    def unlock(self, uri):
        pass

    def export_volume(self, volume_urn):
        """ Serialize a suitable properties file for the
        volume_urn. We include all the objects which are contained in
        the volume.
        """
        storage = RDF.Storage(storage_name='hashes',
                              name='X',
                              options_string="new='yes',hash-type='memory',dir='.'")
        model = RDF.Model(storage)
        
        for urn in aff4.oracle.resolve_list(volume_urn, AFF4_CONTAINS):
            try:
                urn_id = self.get_id(self.urn_db, urn)
            except ValueError: continue
            self.export_model(urn, model)

        self.export_model(volume_urn, model)
        serializer = RDF.Serializer("turtle")
        return serializer.serialize_model_to_string(model)

    def export_dict(self, uri):
        """ Return a dict of all keys/values """
        result = {}
        for attr in self.attribute_db.list_keys():
            if attr.startswith("__"): continue

            try:
                int(attr)
                continue
            except: pass

            values = [ v for v in self.resolve_list(uri, attr, follow_inheritence=False) ]
            if values:
                result[attr] = values
        return result

    def export_model(self, uri, model):
        for attr in self.attribute_db.list_keys():
            if attr.startswith("__"): continue
            
            values = self.resolve_list(uri, attr, follow_inheritence=False)
            for v in values:
                statement=RDF.Statement(RDF.Uri(uri),
                    RDF.Uri(attr),
                    RDF.Node(v))

                model.add_statement(statement)
    
    def export(self, uri, prefix=''):
        """ Export all the properties of uri into the model """
        result = ''
        try:
            urn_id = self.get_id(self.urn_db, uri)
        except ValueError: return ''
        
        for attr in self.attribute_db.list_keys():
            values = self.resolve_list(uri, attr, follow_inheritence=False)
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
        maximum_id = self.urn_db.get(MAX_KEY) or 0
        return int(maximum_id)

    def get_urn_by_id(self, id):
        return self.urn_db.get("%s" % id)

    def get_id(self, tdb, attribute):
        """ Given an attribute returns its ID """
        id = tdb.get(attribute)
        if not id:
            maximum_id = int(tdb.get(MAX_KEY) or 0)
            id = maximum_id = "%d" % (maximum_id + 1)
            tdb.store(MAX_KEY, maximum_id)
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

        ## Check if its already been set
        old_value = self.resolve(uri, attribute)
        if old_value == value: return

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
        value = value.__str__()
        ## Check if we need to add this value
        for x in self.resolve_list(uri, attribute):
            if x==value: return
            
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

    def resolve(self, uri, attribute, follow_inheritence=True):
        """ Return a single (most recently set attribute) """
        for x in self.resolve_list(uri, attribute, follow_inheritence):
            return x

        return NoneObject("No attribute %s found on %s" % (attribute, uri))

    def delete(self, uri, attribute):
        key = self.calculate_key(uri, attribute)
        self.data_db.delete(key)

    def resolve_list(self, uri, attribute, follow_inheritence=True):
        try:
            key = self.calculate_key(uri, attribute)
        except ValueError:
            return
        
        offset = self.data_db.get(key)
        while offset and offset!=-1:
            self.data_store.seek(int(offset))
            offset, length = struct.unpack("<ll", self.data_store.read(8))
            yield self.data_store.read(length)

        if not follow_inheritence:
            return
        
        for inherited in self.resolve_list(uri, AFF4_INHERIT, follow_inheritence=False):
            for v in self.resolve_list(inherited, attribute):
                yield v

NoneObject = aff4.NoneObject

if __name__=="__main__":
    oracle = TDBResolver()
    oracle.add("hello","cruel","world")
    oracle.add("hello","cruel","world2")
    oracle.add("hello","cruel","world3")
    print oracle.resolve_list("hello","cruel")
