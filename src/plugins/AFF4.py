""" This module implements AFF4 support into PyFlag.

The AFF4 design is effectively a virtual filesystem (VFS) in itself
since a single AFF4 volume may contain many streams.

When we load an external AFF4 file into PyFlag we replicate all the
stream objects in the volume inside the VFS.

We have an AFF4 VFSFile object which is able to access these files.
"""

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

#aff4.oracle.set(aff4.GLOBAL, aff4.CONFIG_VERBOSE, 20)

## This is a persistent resolver in the database
NEW_OBJECTS = []

## All the attributes we know about
ATTRIBUTES = {}

## Some private AFF4 namespace objects
PYFLAG_NS = "urn:pyflag:"
PYFLAG_CASE = PYFLAG_NS + "case"

## These are the supported streams
SUPPORTED_STREAMS = [AFF4_IMAGE, AFF4_MAP, AFF4_AFF1_STREAM,
                     AFF4_EWF_STREAM, AFF4_RAW_STREAM]

def resolve_id(urn):
    PDBO = DB.DBO()
    PDBO.execute("select urn_id from AFF4_urn where urn = %r limit 1", urn)
    row = PDBO.fetch()
    
    if row:
        return row.get('urn_id')

def resolve_urn(inode_id):
    PDBO = DB.DBO()
    PDBO.execute("select urn from AFF4_urn where urn_id = %r limit 1", inode_id)
    row = PDBO.fetch()
    
    if row:
        return row.get('urn')

## Attach this method to the oracle
aff4.oracle.resolve_id = resolve_id
aff4.oracle.resolve_urn = resolve_urn

class DBURNObject(aff4.URNObject):
    def __init__(self, urn):
        aff4.URNObject.__init__(self, urn)
        self.properties = {}
        self.urn = urn
        global NEW_OBJECTS
        NEW_OBJECTS.append(self)

        PDBO = DB.DBO()
        self.urn_id = aff4.oracle.resolve_id(urn)
        if self.urn_id:
            PDBO.execute("select attribute, value from AFF4_attribute "
                         "join AFF4 on AFF4.attribute_id = "
                         "AFF4_attribute.attribute_id where urn_id = %r", self.urn_id)
        
            for row in PDBO:
                aff4.URNObject.add(self, row['attribute'], row['value'])
        else:
            PDBO.insert("AFF4_urn",
                        urn=urn)
            self.urn_id = PDBO.autoincrement()
            
    def flush(self, case=None):
        """ Write ourselves to the DB """
        PDBO = DB.DBO()
        case = case or self.properties.get(PYFLAG_CASE,[''])[0]
        PDBO.update("AFF4_urn", _fast=True,
                    where="urn_id = '%s'" % self.urn_id,
                    case=case)
        
        for attribute,values in self.properties.items():
            try:
                attribute_id = ATTRIBUTES[attribute]
            except KeyError:
                PDBO.execute('select attribute_id from AFF4_attribute where attribute = %r',
                            attribute)
                row = PDBO.fetch()
                if row:
                    attribute_id = row['attribute_id']
                else:
                    PDBO.insert("AFF4_attribute", _fast=True,
                                attribute = attribute)
                    attribute_id = PDBO.autoincrement()
                    ATTRIBUTES[attribute] = attribute_id

            for value in values:
                PDBO.insert("AFF4",
                            urn_id = self.urn_id,
                            attribute_id=attribute_id,
                            value=value)

## Install this new implementation in the resolver
aff4.oracle.urn_obj_class = DBURNObject

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

        ## Note that we dont need to maintain any persistant
        ## information about the volumes. Once the volumes are loaded,
        ## their location, streams and all other information will be
        ## stored in the AFF4 universal resolver. Even if PyFlag is
        ## restarted, this information remains valid. In future we can
        ## access the relevant objects directly through the oracle,
        ## and we do not need to maintain it.
        result.heading("Loading AFF4 Volumes")

        global NEW_OBJECTS, ATTRIBUTES
        
        NEW_OBJECTS = []
        
        for f in filenames:
            ## Filenames are always specified relative to the upload
            ## directory
            filename = "file://%s/%s" % (config.UPLOADDIR, f)
            volumes = aff4.load_volume(filename)
            result.row("%s" % volumes)

        aff4.oracle.clear_hooks()
        fsfd = DBFS(query['case'])
        base_dir = os.path.basename(filenames[0])
        for obj in NEW_OBJECTS:
            type = obj[AFF4_TYPE][0]
            if type in SUPPORTED_STREAMS:
                urn = obj.urn
                if "/" in urn:
                    path = "%s/%s" % (base_dir, urn[urn.index("/"):])
                else:
                    path = base_dir

                fsfd.VFSCreate(urn, path, _fast=True,
                               mode=-1)
                        
            obj.flush(query['case'])

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
    
    def init_default_db(self, dbh, case):
        ## Denormalise these tables for speed and efficiency
        dbh.execute("""CREATE TABLE if not exists
        AFF4_urn (
        `urn_id` int unsigned not null auto_increment primary key,
        `case` varchar(50) default NULL,
        `urn` varchar(2000) default NULL
        ) engine=MyISAM""")

        dbh.execute("""CREATE TABLE if not exists
        AFF4_attribute (
        `attribute_id` int unsigned not null auto_increment primary key,
        `attribute` varchar(2000) default NULL
        ) engine=MyISAM;""")

        dbh.execute("""CREATE TABLE if not exists
        AFF4 (
        `urn_id` int unsigned not null ,
        `attribute_id` int unsigned not null ,
        `value` varchar(2000) default NULL
        ) engine=MyISAM;""")
        
        dbh.check_index("AFF4_urn", "urn", 100)
        dbh.check_index("AFF4_attribute", "attribute", 100)
        dbh.check_index("AFF4", "urn_id")
        dbh.check_index("AFF4", "attribute_id")

    def reset(self, dbh, case):
        ## Remove all the urns that belong to this case
        pdbh = DB.DBO()
        pdbh2 = DB.DBO()
        pdbh.execute("select * from AFF4_urn where `case`=%r", case)
        for row in pdbh:
            urn_id = row['urn_id']
            pdbh2.delete("AFF4", where='urn_id="%s"' % urn_id, _fast=True)

        pdbh.delete("AFF4_urn", where='`case`="%s"' % case, _fast=True)

    def create(self, dbh, case):
        """ Create a new case AFF4 Result file """
        volume = aff4.ZipVolume(None, 'w')
        aff4.oracle.set(volume.urn, aff4.AFF4_STORED, "%s/%s.aff4" % (config.RESULTDIR, case))
        volume.finish()
        aff4.oracle.cache_return(volume)
        dbh.set_meta("result_aff4_volume", volume.urn)

    def periodic(self, dbh, case):
        return
        dbh = DB.DBO()
        dbh.execute("select value from meta where property='flag_db'")
        for row in dbh:
            case = row['value']
            volume_urn = aff4.oracle.resolve("%s/%s.aff4" % (config.RESULTDIR, case),
                                             aff4.AFF4_CONTAINS)
            print "Closing AFF4 file %s" % aff4.oracle.resolve(volume_urn, aff4.AFF4_VOLATILE_DIRTY)
            
    def startup(self):
        dbh = DB.DBO()
        try:
            dbh.execute("desc AFF4")
        except: self.init_default_db(dbh, None)
        
## FIXME - move to Core.py
from pyflag.ColumnTypes import StringType, TimestampType, AFF4URN, FilenameType, IntegerType, DeletedType, SetType, BigIntegerType, StateType

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

    extras = [ [FilenameType, dict(table='vfs', name='Name', basename=True)] ]
    
import unittest
import pyflag.pyflagsh as pyflagsh

class AFF4LoaderTest(unittest.TestCase):
    """ Load handling of AFF4 volumes """
    test_case = "PyFlagTestCase"
    test_file = 'pcap.zip'

    def test01CaseCreation(self):
        pyflagsh.shell_execv(command="delete_case",
                             argv=[self.test_case])
        pyflagsh.shell_execv(command="create_case",
                             argv=[self.test_case])
        if 1:
            pyflagsh.shell_execv(command='execute',
                                 argv=['Load Data.Load AFF4 Volume',
                                       'case=%s' % self.test_case, 
                                       'filename=%s' % self.test_file])
        fd = CacheManager.AFF4_MANAGER.create_cache_fd(self.test_case, "/foo/bar/test.txt")
        fd.write("hello world")
        fd.close()

import atexit

def FlushResolver():
    for obj in aff4.oracle.urn.values():
        obj.flush()

atexit.register(FlushResolver)
