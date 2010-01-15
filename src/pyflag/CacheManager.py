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

Since the introduction of AFF4, all locking is not done by the AFF4
resolver.

"""
import pyflag.conf
config=pyflag.conf.ConfObject()
import cStringIO, os, os.path
import pyflag.DB as DB
import pdb
import pyflag.Registry as Registry
import cPickle, urllib
import pyaff4
from pyflag.attributes import *
import time

oracle = pyaff4.Resolver()

initialised = False

class PyFlagRDFType:
    dataType = PYFLAG_RDFTYPE
    value = None

    def encode(self):
        return cPickle.dumps(self.value, protocol=1)

    def decode(self, data):
        self.value = cPickle.loads(data)

    def serialise(self):
        result = cPickle.dumps(self.value, protocol=1)

        return urllib.quote(result)

    def parse(self, data):
        result = urllib.unquote(data)

        self.value = cPickle.loads(result)

    def set(self, value):
        self.value = value

class PyFlagAFF4Renderer:
    def message(self, level, message):
        pass

if not initialised:
    time.sleep(1)

## Now we register this class as an RDFValue type
if not initialised:
    oracle.register_rdf_value_class(pyaff4.ProxiedRDFValue(PyFlagRDFType))
    oracle.set_logger(pyaff4.ProxiedLogger(PyFlagAFF4Renderer()))

initialised = True


def update_table_from_urn(case, urn):
    ## We need to do this explicitely because we might end up
    ## inserting to tables our inherited object specifies. This
    ## essentially maintains a copy of all the attribute in our
    ## inherited object in the same table.
    dbh = DB.DBO(case)
    value = oracle.new_rdfvalue(PYFLAG_RDFTYPE)
    inode_id = oracle.get_id_by_urn(urn)

    for table, columns in Registry.CASE_TABLES.case_tables.items():
        for data_urn in oracle.resolve_list(urn, "%s%s" % (PYFLAG_NS, table)):
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

    oracle.add_value(urn, "%s%s" % (PYFLAG_NS, table),
               cPickle.dumps(result,protocol=2).encode("string_escape"))

class AFF4Proxy:
    """ This class proxies an AFF4 object using its URN """
    def __init__(self, obj):
        self.obj = obj
        self.inode_id = oracle.get_id_by_urn(obj.urn)

        ## Hold onto these properties ourselves because we close our
        ## object and then need to use them
        self.size = obj.size
        self.urn = obj.urn

    def __getattr__(self, attr):
        """ This is only useful for proper methods (not ones that
        start with __ )
        """
        ## Search for the attribute of the proxied object
        return getattr(self.obj, attr)

    def __repr__(self):
        return "<Proxy for %s>" % self.obj

class PyFlagMap(AFF4Proxy):
    include_in_VFS = None
    end_of_line = '\r\n'

    ## We seem to get a good speed up if we do the caching here rather
    ## than in aff4.FileLikeObject because we really reduce lock
    ## contention. It seems that locking is rather expensive.
    def readline(self, size=1024):
        idx = None
        try:
            ## We try to find the marker in the lookahead buffer. This
            ## check protects us from seeks or reads that were done
            ## out of sync with readline()
            assert(self.readptr == self.lookahead_readptr)
            idx = self.lookahead.index(self.end_of_line)

        except (AttributeError, ValueError, AssertionError): 
            ## There is no lookahead buffer, or mark not found in the
            ## current buffer. Refresh the lookahead buffer.
            self.lookahead_readptr = self.readptr
            self.lookahead = self.read(size)
            self.readptr = self.lookahead_readptr

        ## Try to find it again in the new buffer:
        try:
            if idx == None:
                idx = self.lookahead.index(self.end_of_line)
        except ValueError:
            ## If the mark is still not found in the buffer, we just
            ## return the whole buffer. The lookahead buffer will be
            ## refreshed next time.
            self.readptr += len(self.lookahead)
            return self.lookahead

        ## If we get here, the end_of_line was found in the lookahead
        ## - we adjust the buffer and return it:
        idx += len(self.end_of_line)
        self.lookahead, data = self.lookahead[idx:], self.lookahead[:idx]

        ## Update the new readptrs for the buffer and the fd:
        self.readptr = self.lookahead_readptr = self.lookahead_readptr + idx

        return data

    def insert_to_table(self, table, props):
        """ This function adds the properties for this object as
        attributes in the urn:pyflag: namespace.
        """
        #urn_insert_to_table(self.urn, table, props)

    def update_tables(self):
        #update_table_from_urn(self.case, self.urn)
        if self.include_in_VFS:
            self.add_to_VFS(**self.include_in_VFS)

    def add_to_VFS(self, path, **kwargs):
        import pyflag.FileSystem as FileSystem

        ## Insert the new fd into the VFS
        fsfd = FileSystem.DBFS(self.case)
        fsfd.VFSCreate(self.urn, path, inode_id = self.inode_id,
                       **kwargs)

    def close(self):
        ## Close first to update size property
        self.obj.close(self)

        ## Now sync the db from the RDF
        self.update_tables()

    def cache_return(self):
        ## Now sync the db from the RDF
        self.update_tables()
        self.obj.cache_return()

class PyFlagImage(PyFlagMap):
    def close(self):
        self.obj.close(self)
        self.update_tables()

class PyFlagSegment(AFF4Proxy):
    def __init__(self, case, volume_urn, segment_urn, data=''):
        data = str(data)

        self.urn = segment_urn
        self.buffer = cStringIO.StringIO()
        self.buffer.write(data)
        self.inode_id = oracle.get_id_by_urn(segment_urn, create_new=True)
        self.case = case
        self.size = len(data)
        self.volume_urn = volume_urn

    def finish(self):
        self.inode_id = oracle.get_id_by_urn(self.urn)

    def write(self, data):
        self.buffer.seek(0,2)
        self.buffer.write(data)

    def seek(self, offset, whence=0):
        return self.buffer.seek(offset,whence)

    def tell(self):
        return self.buffer.tell()

    def close(self):
        pdb.set_trace()
        volume = oracle.open(self.volume_urn, 'w')
        try:
            oracle.set_value(self.urn, pyaff4.AFF4_STORED, self.volume_urn)
            volume.writestr(self.urn, self.buffer.getvalue(),
                            compress_type = pyaff4.ZIP_DEFLATED,
                            timestamp = oracle.resolve(self.urn, pyaff4.AFF4_TIMESTAMP) or 0)
        finally:
            volume.cache_return()

        self.update_tables()

class AFF4Manager:
    """ A Special Cache manager which maintains the main AFF4 Cache
    """
    def __init__(self):
        self.volume_urns = {}

    def expire(self, case):
        try:
            volume_urn = self.volume_urns[case]
        except KeyError:
            volume_urn = self.create_volume(case)

        pdb.set_trace()
        try:
            t = time.time()
            oracle.expire(volume_urn)
            print "Expired %s in %s sec" % (volume_urn.value, time.time() -t)

            del self.volume_urns[case]
            self.create_volume(case)
        except KeyError:
            pass

    def create_volume(self, case):
        """ Create a new case AFF4 Result file """
        urn = pyaff4.RDFURN()
        urn.set(config.RESULTDIR)
        urn.add("%s.aff4" % case)

        ## Try to open an existing volume
        if  not oracle.load(urn):
            volume = oracle.create(pyaff4.AFF4_ZIP_VOLUME, 'w')
            oracle.set_value(volume.urn, pyaff4.AFF4_STORED, urn)
            volume = volume.finish()
            urn.set(volume.urn.value)
            volume.cache_return()

        ## Keep the volume urn associated with this case (NOTE this is
        ## not the same as the file URI for the volume itself.
        self.volume_urns[case] = urn

        return urn

    def close(self, case):
        try:
            volume_urn = self.volume_urns[case]
        except KeyError:
            volume_urn = self.create_volume(case)

        volume = oracle.open(volume_urn, 'w')
        volume.close()

    def create_cache_data(self, case, path, data='', include_in_VFS=True,
                          timestamp = None, size=0,
                          inherited = None,**kwargs):
        """ Creates a new AFF4 segment. A segment is useful for 
        storing small amounts of data in a single compressed file.

        We return the URN of the created object so callers can use
        this to set properties on it.
        """
        try:
            volume_urn = self.volume_urns[case]
        except KeyError:
            volume_urn = self.create_volume(case)

        fd = oracle.create(pyaff4.AFF4_IMAGE, 'w')
        fd.urn.set(self.volume_urns[case].value)
        fd.urn.add_query(path)
        fd.size.set(size)

        if timestamp:
            if not isinstance(timestamp, pyaff4.XSDDatetime):
                t = pyaff4.XSDDatetime()
                t.set(timestamp)
            else:
                t = timestamp

            oracle.set_value(fd.urn, pyaff4.AFF4_TIMESTAMP, t)

        oracle.set_value(fd.urn, pyaff4.AFF4_STORED, volume_urn)
        fd = fd.finish()
        fd = PyFlagImage(fd)

        kwargs['path'] = path
        fd.case = kwargs['case'] = case
        if include_in_VFS:
            fd.include_in_VFS = kwargs

        return fd

    def create_cache_fd(self, case, path, include_in_VFS=True, size=0,
                        inherited = None, timestamp = None, compression=True,
                        **kwargs):
        """ Creates a new non-seakable AFF4 Image stream that can be
        written on.

        Callers must call close() on the returned object when they are
        done. The new object will be added to the VFS at path (and
        that is what its URN will be too relative to the volume).
        """
        try:
            volume_urn = self.volume_urns[case]
        except KeyError:
            volume_urn = self.create_volume(case)

        fd = oracle.create(pyaff4.AFF4_IMAGE, 'w')
        fd.urn.set(self.volume_urns[case].value)
        fd.urn.add_query(path)
        fd.size.set(size)

        oracle.set_value(fd.urn, pyaff4.AFF4_STORED, volume_urn)
        ## If a timestamp was specified we set it - otherwise we just
        ## take it from our inherited URN
        if timestamp:
            if not isinstance(timestamp, pyaff4.XSDDatetime):
                t = pyaff4.XSDDatetime()
                t.set(timestamp)
            else:
                t = timestamp

            oracle.set_value(fd.urn, pyaff4.AFF4_TIMESTAMP, t)

        fd = fd.finish()
        fd = PyFlagImage(fd)

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
        try:
            volume_urn = self.volume_urns[case]
        except KeyError:
            volume_urn = self.create_volume(case)

        fd = oracle.create(pyaff4.AFF4_MAP, 'w')
        urn = fd.urn
        urn.set(self.volume_urns[case].value)
        urn.add_query(path)
        if size:
            fd.size.set(size)

        #FIXME:
        #if inherited:
        #    fd.set_inheritence(inherited)

        if target:
            oracle.set_value(urn, pyaff4.AFF4_TARGET, target)

        oracle.set_value(urn, pyaff4.AFF4_STORED, volume_urn)
        ## If a timestamp was specified we set it - otherwise we just
        ## take it from our inherited URN
        if timestamp:
            if not isinstance(timestamp, pyaff4.XSDDatetime):
                t = pyaff4.XSDDatetime()
                t.set(timestamp)
            else:
                t = timestamp

            oracle.set_value(urn, pyaff4.AFF4_TIMESTAMP, t)

        fd = fd.finish()
        fd = PyFlagMap(fd)

        kwargs['path'] = path
        fd.case = kwargs['case'] = case
        if include_in_VFS:
            fd.include_in_VFS = kwargs

        return fd

    def create_link(self, case, source, destination, include_in_VFS=True, **kwargs):
        """ Creates a link object from source urn to destination urn """
        import pyflag.FileSystem as FileSystem

        volume_urn = self.volume_urns[case]
        urn = pyaff4.RDFURN()
        urn.set(volume_urn.value)
        urn.add(destination)

        ## Add the new link to the VFS:
        fsfd = FileSystem.DBFS(case)
        fsfd.VFSCreate(source, urn.parser.query,
                       **kwargs)

AFF4_MANAGER = AFF4Manager()
