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

def update_table_from_urn(case, urn):
    ## We need to do this explicitely because we might end up
    ## inserting to tables our inherited object specifies. This
    ## essentially maintains a copy of all the attribute in our
    ## inherited object in the same table.
    dbh = DB.DBO(case)
    inode_id = aff4.oracle.get_id_by_urn(urn)
    
    for table, columns in Registry.CASE_TABLES.case_tables.items():
        for data_urn in aff4.oracle.resolve_list(urn, "%s%s" % (PYFLAG_NS, table)):
            args = {'inode_id': inode_id}
            args.update(cPickle.loads(data_urn.decode("string_escape")))
            dbh.insert(table, _fast=True, **args)

def urn_insert_to_table(urn, table, props):
    ## Make sure we dont have inode id
    try:
        del props['inode_id']
    except: pass

    ## Flatten out the props dictionary
    result = {}
    for k,v in props.items():
        if type(v)==unicode:
            v = v.encode("utf8",'ignore')
        else:
            v = str(v)

        result[k] = v

    aff4.oracle.add(urn, "%s%s" % (PYFLAG_NS, table),
                    cPickle.dumps(result,protocol=2).encode("string_escape"))

class PyFlagMap(aff4.Map):
    include_in_VFS = None
    
    def insert_to_table(self, table, props):
        """ This function adds the properties for this object as
        attributes in the urn:pyflag: namespace.
        """
        urn_insert_to_table(self.urn, table, props)

    def update_tables(self):
        update_table_from_urn(self.case, self.urn)
        if self.include_in_VFS:
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
        self.inode_id = aff4.oracle.get_id_by_urn(self.urn)

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
        self.inode_id = aff4.oracle.get_id_by_urn(self.urn)

class PyFlagSegment(PyFlagMap):
    def __init__(self, case, volume_urn, segment_urn, data=''):
        data = str(data)
        
        self.urn = segment_urn
        self.buffer = cStringIO.StringIO()
        self.buffer.write(data)
        self.inode_id = aff4.oracle.get_id_by_urn(segment_urn, create_new=True)
        self.case = case
        self.size = len(data)
        self.volume_urn = volume_urn

    def finish(self):
        self.inode_id = aff4.oracle.get_id_by_urn(self.urn)
        
    def write(self, data):
        self.buffer.seek(0,2)
        self.buffer.write(data)

    def seek(self, offset, whence=0):
        return self.buffer.seek(offset,whence)
        
    def tell(self):
        return self.buffer.tell()
        
    def close(self):
        volume = aff4.oracle.open(self.volume_urn, 'w')
        try:
            aff4.oracle.set(self.urn, AFF4_STORED, self.volume_urn)
            #aff4.oracle.set(self.urn, PYFLAG_CASE, self.case)
            volume.writestr(self.urn, self.buffer.getvalue(),
                            compress_type = aff4.ZIP_DEFLATED,
                            timestamp = aff4.oracle.resolve(self.urn, AFF4_TIMESTAMP) or 0)
        finally:
            aff4.oracle.cache_return(volume)
        
        self.update_tables()

class AFF4Manager:
    """ A Special Cache manager which maintains the main AFF4 Cache
    """
    def make_volume_filename(self, case):
        return "%s.aff4" % (case)

    def create_volume(self, case):
        """ Create a new case AFF4 Result file """
        volume = aff4.ZipVolume(None, 'w')
        filename = self.make_volume_filename(case)
        aff4.oracle.set(volume.urn, aff4.AFF4_STORED, filename)
        aff4.oracle.set(filename, aff4.AFF4_CONTAINS, volume.urn)
        volume.finish()
        aff4.oracle.cache_return(volume)

        return volume.urn

    def make_volume_urn(self, case):
        volume_path = self.make_volume_filename(case)
        volume_urn = aff4.oracle.resolve(volume_path, aff4.AFF4_CONTAINS)

        if not volume_urn:
            ## Volume does not exist - we need to make a new one for
            ## this case:
            return self.create_volume(case)

        return volume_urn

    def close(self, case):
        volume_urn = self.make_volume_urn(case)
        volume = aff4.oracle.open(volume_urn, 'w')
        volume.close()

    def create_cache_data(self, case, path, data='', include_in_VFS=True,
                          timestamp = None,
                          inherited = None,**kwargs):
        """ Creates a new AFF4 segment. A segment is useful for 
        storing small amounts of data in a single compressed file.

        We return the URN of the created object so callers can use
        this to set properties on it.
        """
        ## Drop the FQN from the path
        if path.startswith(FQN) and "/" in path:
            path = path[path.index("/"):]

        volume_urn = self.make_volume_urn(case)
        urn = aff4.fully_qualified_name(path, volume_urn)
        fd = PyFlagSegment(case, volume_urn, urn, data)

        if timestamp:
            aff4.oracle.set(fd.urn, AFF4_TIMESTAMP, timestamp)

        if inherited:
            assert(type(inherited) == str)
            fd.set_inheritence(inherited)

        fd.finish()

        kwargs['path'] = path
        if include_in_VFS:
            fd.include_in_VFS = kwargs
            
        return fd
        
    def create_cache_fd(self, case, path, include_in_VFS=True,
                        inherited = None, timestamp = None,
                        **kwargs):
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

        if timestamp:
            aff4.oracle.set(fd.urn, AFF4_TIMESTAMP, timestamp)

        if inherited:
            fd.set_inheritence(inherited)

        aff4.oracle.set(fd.urn, AFF4_STORED, volume_urn)
        #aff4.oracle.set(fd.urn, PYFLAG_CASE, case)
        fd.finish()

        kwargs['path'] = path
        fd.case = kwargs['case'] = case

        if include_in_VFS:
            fd.include_in_VFS = kwargs

        return fd

    def create_cache_map(self, case, path, include_in_VFS=True, size=0,
                         target = None, inherited = None, timestamp = 0,
                         **kwargs):
        """ Creates a new map in the VFS.

        Callers must call close() on the object to ensure it gets
        written to the volume. The returned object is a standard AFF4
        map object and supports all the methods from the AFF4 library.
        """
        #pdb.set_trace()
        ## Drop the FQN from the path
        if path.startswith(FQN) and "/" in path:
            path = path[path.index("/"):]

        fd = PyFlagMap(None, 'w')
        fd.size = size
        volume_urn = self.make_volume_urn(case)
        fd.urn = aff4.fully_qualified_name(path, volume_urn)
        if inherited:
            fd.set_inheritence(inherited)
        
        if target:
            aff4.oracle.set(fd.urn, AFF4_TARGET, target)
            
        aff4.oracle.set(fd.urn, AFF4_STORED, volume_urn)
        ## If a timestamp was specified we set it - otherwise we just
        ## take it from our inherited URN
        if timestamp:
            aff4.oracle.set(fd.urn, AFF4_TIMESTAMP, timestamp)
            
        #aff4.oracle.set(fd.urn, PYFLAG_CASE, case)
        fd.finish()
        
        kwargs['path'] = path
        fd.case = kwargs['case'] = case
        if include_in_VFS:
            fd.include_in_VFS = kwargs

        return fd

    def create_link(self, case, source, destination, include_in_VFS=True, **kwargs):
        """ Creates a link object from source urn to destination urn """
        import pyflag.FileSystem as FileSystem

        volume_urn = self.make_volume_urn(case)
        urn = aff4.fully_qualified_name(destination, volume_urn)
        
        ## Links are managed through inheritance now
        aff4.oracle.set(urn, AFF4_INHERIT, source)

        ## Add the new link to the VFS:
        fsfd = FileSystem.DBFS(case)
        destination_path = aff4.relative_name(destination, volume_urn)
        fsfd.VFSCreate(urn, destination_path,
                       **kwargs)
        
AFF4_MANAGER = AFF4Manager()
