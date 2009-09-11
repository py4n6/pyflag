""" This module implements a Cache Manager.

A Cache manager is a coordinated way of gaining access to the object
cache on disk. PyFlag keeps many objects cached on disk for fast
access. The cache manager manages the specific organization of cache
objects, and provides a unified API for accessing and creating these
objects.

Design documentation for Cache managers
---------------------------------------

The Cache manager is a singleton object within the process (i.e. all
threads use the same manager). The currently active manager is
instantiated in the module variable MANAGER.

The manager needs to handle synchronous access from multiple threads
within this process, as well as multiple processes, and even processes
on multiple machines. This is because many workers can have access to
the same cache and workers can be distributed in a very flexible
way. This implies that its not enough to use thread locks, or even
filesystem locks (unless the filesystem locks are shared across the
network properly say over SMB). Database locks are probably the best
method of synchronization.

"""
import pyflag.conf
config=pyflag.conf.ConfObject()
import cStringIO, os, os.path
import pyflag.DB as DB
import pdb
import pyflag.Registry as Registry
import pyflag.aff4.aff4 as aff4
from pyflag.aff4.aff4_attributes import *
import cPickle

## Some private AFF4 namespace objects
PYFLAG_NS = "urn:pyflag:"
PYFLAG_CASE = PYFLAG_NS + "case"

class PyFlagMap(aff4.Map):
    include_in_VFS = {}
    def insert_to_table(self, table, props):
        """ This function adds the properties for this object as
        attributes in the urn:pyflag: namespace.
        """
        ## Make sure we dont have inode id
        try:
            del props['inode_id']
        except: pass
        
        aff4.oracle.add(self.urn, "%s%s" % (PYFLAG_NS, table),
                        cPickle.dumps(props, protocol=0))
        #aff4.oracle.set(self.urn, "%s%s" % (PYFLAG_NS, table), "1")
        #for k,v in props.items():
        #    aff4.oracle.set(self.urn, "%s%s:%s" % (PYFLAG_NS, table, k), v)

    def update_tables(self):
        #pdb.set_trace()
        ## We need to do this explicitely because we might end up
        ## inserting to tables our inherited object specifies. This
        ## essentially maintains a copy of all the attribute in our
        ## inherited object in the same table.
        dbh = DB.DBO(self.case)
        for table, columns in Registry.CASE_TABLES.case_tables.items():
            #if table=='connection_details': pdb.set_trace()
            
            for data in aff4.oracle.resolve_list(self.urn, "%s%s" % (PYFLAG_NS, table)):
                args = {'inode_id': self.inode_id}                
                tmp_args = cPickle.loads(data)
                for column in columns:
                    try:
                        args[column] = tmp_args[column]
                    except KeyError:
                        try:
                            args["_"+column] = tmp_args["_"+column]
                        except KeyError:
                            pass
                    
                dbh.insert(table, **args)

        self.add_to_VFS(**self.include_in_VFS)

    def add_to_VFS(self, path, **kwargs):
        import pyflag.FileSystem as FileSystem

        ## Insert the new fd into the VFS
        fsfd = FileSystem.DBFS(self.case)
        fsfd.VFSCreate(self.urn, path, inode_id = self.inode_id,
                       **kwargs)

    def finish(self):
        aff4.Map.finish(self)
        
        ## Come up with a valid inode_id
        self.inode_id = aff4.oracle.resolve_id(self.urn)

    def close(self):
        aff4.Map.close(self)
        self.update_tables()
        
class PyFlagImage(aff4.Image, PyFlagMap):
    def close(self):
        aff4.Image.close(self)
        self.update_tables()

    def finish(self):
        aff4.Image.finish(self)
        
        ## Come up with a valid inode_id
        self.inode_id = aff4.oracle.resolve_id(self.urn)


class AFF4Manager:
    """ A Special Cache manager which maintains the main AFF4 Cache
    """
    def make_volume_urn(self, case):
        volume_path = "file://%s/%s.aff4" % (config.RESULTDIR, case)
        volume_urn = aff4.oracle.resolve(volume_path, aff4.AFF4_CONTAINS)

        return volume_urn
        
    def create_cache_fd(self, case, path, include_in_VFS=True,
                        inherited = None,**kwargs):
        """ Creates a new non-seakable AFF4 Image stream that can be
        written on.
        
        Callers must call close() on the returned object when they are
        done. The new object will be added to the VFS at path (and
        that is what its URN will be too relative to the volume).
        """
        ## Drop the FQN from the path
        if path.startswith(FQN) and "/" in path:
            path = path[path.index("/"):]

        fd = PyFlagImage(None, 'w')
        volume_urn = self.make_volume_urn(case)
        fd.urn = aff4.fully_qualified_name(path, volume_urn)
        aff4.oracle.set(fd.urn, AFF4_STORED, volume_urn)
        aff4.oracle.set(fd.urn, PYFLAG_CASE, case)
        fd.finish()

        kwargs['path'] = path
        fd.case = case
        if include_in_VFS:
            fd.include_in_VFS = kwargs

        if inherited:
            aff4.oracle.set(fd.urn, AFF4_INHERIT, inherited)
            
        return fd

    def create_cache_map(self, case, path, include_in_VFS=True, size=0,
                         target = None, inherited = None,
                         **kwargs):
        """ Creates a new map in the VFS.

        Callers must call close() on the object to ensure it gets
        written to the volume. The returned object is a standard AFF4
        map object and supports all the methods from the AFF4 library.
        """
        ## Drop the FQN from the path
        if path.startswith(FQN) and "/" in path:
            path = path[path.index("/"):]

        fd = PyFlagMap(None, 'w')
        fd.size = size
        volume_urn = self.make_volume_urn(case)
        fd.urn = aff4.fully_qualified_name(path, volume_urn)
        if target:
            aff4.oracle.set(fd.urn, AFF4_TARGET, target)
            
        aff4.oracle.set(fd.urn, AFF4_STORED, volume_urn)
        aff4.oracle.set(fd.urn, PYFLAG_CASE, case)
        fd.finish()
        
        kwargs['path'] = path
        fd.case = kwargs['case'] = case
        if include_in_VFS:
            fd.include_in_VFS = kwargs

        if inherited:
            aff4.oracle.set(fd.urn, AFF4_INHERIT, inherited)
        
        return fd

    def create_link(self, case, source, destination, include_in_VFS=True, **kwargs):
        """ Creates a link object from source urn to destination urn """
        fd = aff4.Link(None, 'w')
        volume_urn = self.make_volume_urn(case)
        fd.urn = aff4.fully_qualified_name(destination, volume_urn)
        aff4.oracle.set(fd.urn, AFF4_STORED, volume_urn)
        aff4.oracle.set(fd.urn, PYFLAG_CASE, case)
        aff4.oracle.set(fd.urn, AFF4_TARGET, aff4.fully_qualified_name(source, volume_urn))
        fd.finish()
        fd.close()

        kwargs['path'] = path
        kwargs['case'] = case
        fd.include_in_VFS = kwargs
        
        return fd
        
AFF4_MANAGER = AFF4Manager()
