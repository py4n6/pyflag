""" This module implements AFF4 support into PyFlag.

The AFF4 design is effectively a virtual filesystem (VFS) in itself
since a single AFF4 volume may contain many streams.

When we load an external AFF4 file into PyFlag we replicate all the
stream objects in the volume inside the VFS.

We have an AFF4 VFSFile object which is able to access these files.
"""
import pyflag.pyflaglog as pyflaglog
import pyflag.Farm as Farm

## We just include the pure python implementation of AFF4 in the
## PyFlag source tree.
import pyflag.aff4.aff4 as aff4
from pyflag.aff4.aff4_attributes import *

import pyflag.Reports as Reports
import pyflag.FileSystem as FileSystem
import pyflag.conf as conf
config = conf.ConfObject()
from pyflag.FileSystem import DBFS, File
import pyflag.FlagFramework as FlagFramework
from pyflag.ColumnTypes import StringType
import pyflag.DB as DB
import pdb, os, os.path
import pyflag.CacheManager as CacheManager
import PIL, cStringIO, PIL.ImageFile
import pyflag.Registry as Registry
from pyflag.ColumnTypes import AFF4URN, StringType, FilenameType, DeletedType, IntegerType, TimestampType, BigIntegerType, StateType, ThumbnailType, SetType

## Some private AFF4 namespace objects
PYFLAG_NS = "urn:pyflag:"
PYFLAG_CASE = PYFLAG_NS + "case"

## These are the supported streams
SUPPORTED_STREAMS = [AFF4_IMAGE, AFF4_MAP, AFF4_AFF1_STREAM,
                     AFF4_EWF_STREAM, AFF4_RAW_STREAM]

## Move towards using the tdb resolver for AFF4
import pyflag.aff4.tdb_resolver as tdb_resolver
aff4.oracle = tdb_resolver.TDBResolver()

#aff4.oracle.set(aff4.GLOBAL, aff4.CONFIG_VERBOSE, 20)
aff4.oracle.set(aff4.GLOBAL, CONFIG_PROPERTIES_STYLE, 'combined')

class LoadAFF4Volume(Reports.report):
    """
    Load an AFF4 volume
    -------------------
    
    AFF4 is an advanced open format for forensic evidence storage and
    exchange. This report merges the AFF4 volume directly into the
    current VFS.
    """
    parameters = {"filename": "string", 'path': 'string', "__submit__": "any"}
    name = "Load AFF4 Volume"
    family = "Load Data"
    description = "Load an AFF4 Volume"
    
    def form(self, query, result):
        result.fileselector("Select AFF4 volume:", name='filename', vfs=True)
        try:
            if not query.has_key("path"):
                query['path'] = query['filename']
            result.textfield("Mount point", "path")
        except KeyError: pass

    def display(self, query, result):
        filenames = query.getarray('filename')
        print "Openning AFF4 volume %s" % (filenames,)
        result.heading("Loading AFF4 Volumes")

        loaded_volumes = []
        
        for f in filenames:
            ## Filenames are always specified relative to the upload
            ## directory
            filename = "file://%s/%s" % (config.UPLOADDIR, f)
            volumes = aff4.load_volume(filename)
            result.row("%s" % volumes)
            loaded_volumes.extend(volumes)

        fsfd = DBFS(query['case'])
        base_dir = os.path.basename(filenames[0])

        ## FIXME - record the fact that these volumes are loaded
        ## already into this case...

        ## Load all the objects inside the volumes
        for v in loaded_volumes:
            for urn in aff4.oracle.resolve_list(v, AFF4_CONTAINS):
                type = aff4.oracle.resolve(urn, AFF4_TYPE)
                if type in SUPPORTED_STREAMS:
                    if "/" in urn:
                        path = "%s/%s" % (base_dir, urn[urn.index("/"):])
                    else:
                        path = base_dir

                    fsfd.VFSCreate(urn, path, _fast=True,
                                   mode=-1)

class AFF4File(File):
    """ A VFS driver to read streams from AFF4 stream objects """
    specifier = 'u'

    def __init__(self, case, fd, inode):
        self.urn = inode
        fd = aff4.oracle.open(inode, 'r')
        try:
            if not fd: raise IOError("Unable to open %s" % inode)
        finally:
            aff4.oracle.cache_return(fd)
            
        File.__init__(self, case, fd, inode)

    def cache(self):
        pass

    def close(self):
        pass

    def read(self, length=None):
        fd = aff4.oracle.open(self.urn,'r')
        try:
            fd.seek(self.readptr)
            result = fd.read(length)
        finally:
            aff4.oracle.cache_return(fd)
            
        self.readptr+=len(result)
        
        return result

class AFF4ResolverTable(FlagFramework.EventHandler):
    """ Create tables for the AFF4 universal resolver. """
    
    def create(self, dbh, case):
        """ Create a new case AFF4 Result file """
        volume = aff4.ZipVolume(None, 'w')
        filename = "file://%s/%s.aff4" % (config.RESULTDIR, case)
        aff4.oracle.set(volume.urn, aff4.AFF4_STORED, filename)
        volume.finish()
        aff4.oracle.cache_return(volume)

class AFF4VFS(FlagFramework.CaseTable):
    """ A VFS implementation using AFF4 volumes """
    name = 'vfs'
    indexes = ['urn_id']
    columns = [ [ AFF4URN, {} ],
                [ DeletedType, {} ],
                [ IntegerType, dict(name = 'UID', column = 'uid')],
                [ IntegerType, dict(name = 'GID', column = 'gid')],
                [ TimestampType, dict(name = 'Modified', column='mtime')],
                [ TimestampType, dict(name = 'Accessed', column='atime')],
                [ TimestampType, dict(name = 'Changed', column='ctime')],
                [ TimestampType, dict(name = 'Deleted', column='dtime')],
                [ IntegerType, dict(name = 'Mode', column='mode')],
                [ BigIntegerType, dict(name = 'Size', column='size')],
                ## The type for this object
                [ StateType, dict(name='Type', column='type',
                                  states = dict(directory='directory',
                                                file = 'file'))],
                
                ## The dictionary version used on this inode:
                [ IntegerType, dict(name = "Index Version", column='version', default=0)],
                [ IntegerType, dict(name = 'Desired Version', column='desired_version')],
                ## The filename in the VFS where this object goes
                [ FilenameType, dict(table='vfs')],
                ]

    extras = [ [FilenameType, dict(table='vfs', name='Name', basename=True)],
               [ThumbnailType, dict(table='vfs', name='Thumb')],
               ]

    def __init__(self):
        scanners = set([ "%s" % s.__name__ for s in Registry.SCANNERS.classes ])
        self.columns = self.columns + [ [ SetType,
                                          dict(name='Scanner Cache', column='scanner_cache',
                                               states = scanners)
                                          ],
                                        ]

    
import unittest
import pyflag.pyflagsh as pyflagsh

class AFF4LoaderTest(unittest.TestCase):
    """ Load handling of AFF4 volumes """
    test_case = "PyFlagTestCase"
#    test_file = 'http_small.pcap'
    test_file = 'http.pcap'
#    test_file = '/testimages/pyflag_stdimage_0.5.e01'
#    test_file = 'stdcapture_0.4.pcap.e01'

    def test01CaseCreation(self):
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(command="delete_case", env=env,
                             argv=[self.test_case])
        pyflagsh.shell_execv(command="create_case", env=env,
                             argv=[self.test_case])
        if 1:
            pyflagsh.shell_execv(command='execute', env=env,
                                 argv=['Load Data.Load AFF4 Volume',
                                       'case=%s' % self.test_case, 
                                       'filename=%s' % self.test_file])

            pyflagsh.shell_execv(command='scan', env=env,
                                 argv=['*', 'PartitionScanner',
                                       'FilesystemLoader', 'PCAPScanner',
                                       'HTTPScanner', 'GZScan'])
            
        #fd = CacheManager.AFF4_MANAGER.create_cache_fd(self.test_case, "/foo/bar/test.txt")
        #fd.write("hello world")
        #fd.close()


import atexit

def close_off_volume():
    """ Check for dirty volumes are closes them """
    dbh = DB.DBO()
    dbh.execute("select value from meta where property='flag_db'")
    for row in dbh:
        volume_urn = CacheManager.AFF4_MANAGER.make_volume_urn(row['value'])
        if volume_urn and aff4.oracle.resolve(volume_urn, AFF4_VOLATILE_DIRTY):
            fd = aff4.oracle.open(volume_urn, 'w')
            print "Closing volume %s" % volume_urn
            if fd:
                fd.close()

atexit.register(close_off_volume)
