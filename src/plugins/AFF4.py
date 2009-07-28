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
import pyflag.Reports as Reports
import pyflag.FileSystem as FileSystem
import pyflag.conf as conf
config = conf.ConfObject()
from pyflag.FileSystem import DBFS, File
import pyflag.FlagFramework as FlagFramework
from pyflag.ColumnTypes import StringType
import pyflag.DB as DB
import pdb

#aff4.oracle.set(aff4.GLOBAL, aff4.CONFIG_VERBOSE, 20)

## This is a persistent resolver in the database
NEW_OBJECTS = []

## All the attributes we know about
ATTRIBUTES = {}

class DBURNObject(aff4.URNObject):
    def __init__(self, urn):
        aff4.URNObject.__init__(self, urn)
        self.properties = {}
        self.urn = urn
        NEW_OBJECTS.append(self)

        PDBO = DB.DBO()
        PDBO.execute("select urn_id from AFF4_urn where urn = %r limit 1", urn)
        row = PDBO.fetch()

        if row:
            self.urn_id = row['urn_id']
            PDBO.execute("select attribute, value from AFF4_attribute "
                         "join AFF4 on AFF4.attribute_id = "
                         "AFF4_attribute.attribute_id where urn_id = %r", self.urn_id)
        
            for row in PDBO:
                aff4.URNObject.add(self, row['attribute'], row['value'])

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
    parameters = {"filename": "string"}
    name = "Load AFF4 Volume"
    family = "Load Data"
    description = "Load an AFF4 Volume"
    
    def form(self, query, result):
        result.fileselector("Select AFF4 volume:", name='filename', vfs=True)

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

        ## We maintain oracle streams in the VFS automatically - by
        ## installing an oracle add hook, we can be notified of any
        ## new objects that are created, and populate the VFS with
        ## them.
        fsfd = DBFS(query['case'])
        
        def VFS_Update(urn, attribute, value):
            if attribute==aff4.AFF4_TYPE and value in \
                   [aff4.AFF4_IMAGE, aff4.AFF4_MAP]:
                fsfd.VFSCreate(None, urn, "/urn:aff4/"+urn, _fast=True, mode=-1)
                if "/" in urn:
                    path = urn[urn.index("/"):]
                    fsfd.VFSCreate(None, urn, path, _fast=True, mode=-1)
                    
        aff4.oracle.register_set_hook(VFS_Update)
        aff4.oracle.register_add_hook(VFS_Update)
        global NEW_OBJECTS, ATTRIBUTES
        
        NEW_OBJECTS = []
        
        for f in filenames:
            ## Filenames are always specified relative to the upload
            ## directory
            filename = "file://%s/%s" % (config.UPLOADDIR, f)
            aff4.load_volume(filename)
            result.row(f)

        aff4.oracle.clear_hooks()
        PDBO = DB.DBO()
        for obj in NEW_OBJECTS:
            for attribute,values in obj.properties.items():
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
                    try:
                        ## URN ID is already known
                        urn_id = obj.urn_id
                    except:
                        ## Make a new URN ID
                        PDBO.insert("AFF4_urn", _fast=True,
                                    case = query['case'],
                                    urn = obj.urn)
                        obj.urn_id = urn_id = PDBO.autoincrement()

                    PDBO.insert("AFF4",
                                urn_id = urn_id,
                                attribute_id=attribute_id,
                                value=value)
        
import pdb

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
        
    def startup(self):
        dbh = DB.DBO()
        try:
            dbh.execute("desc AFF4")
        except: self.init_default_db(dbh, None)

import unittest
import pyflag.pyflagsh as pyflagsh

class AFF4LoaderTest(unittest.TestCase):
    """ Load handling of AFF4 volumes """
    test_case = "PyFlagTestCase"
    test_file = 'pcap.zip'

    def test01CaseCreation(self):
        pyflagsh.shell_execv(command="execute",
                             argv=["Case Management.Remove case",'remove_case=%s' % self.test_case])
        
        pyflagsh.shell_execv(command="execute",
                             argv=["Case Management.Create new case",'create_case=%s' % self.test_case])
        pyflagsh.shell_execv(command='execute',
                             argv=['Load Data.Load AFF4 Volume',
                                   'case=%s' % self.test_case, 
                                   'filename=%s' % self.test_file])
