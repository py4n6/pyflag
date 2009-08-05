""" This module implements AFF4 support into PyFlag.

The AFF4 design is effectively a virtual filesystem (VFS) in itself
since a single AFF4 volume may contain many streams.

When we load an external AFF4 file into PyFlag we replicate all the
stream objects in the volume inside the VFS.

We have an AFF4 VFSFile object which is able to access these files.
"""

## We just include the pure python implementation of AFF4 in the
## PyFlag source tree.
import pyflag.pyflaglog as pyflaglog
import pyflag.Farm as Farm
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

ATTRIBUTE_CACHE = {}

def get_attribute_id(attribute):
    global ATTRIBUTE_CACHE
    try:
        return ATTRIBUTE_CACHE[attribute]
    except KeyError:
        pass

    dbh = DB.DBO()
    dbh.execute("select * from AFF4_attribute where attribute = %r", attribute)
    row = dbh.fetch()
    if row:
        attribute_id = row['attribute_id']
    else:
        dbh.insert("AFF4_attribute", _fast=True,
                   attribute = attribute)
        attribute_id = dbh.autoincrement()

    ATTRIBUTE_CACHE[attribute] = attribute_id
    return attribute_id


class DBURNObject(aff4.URNObject):
    def __init__(self, urn):
        aff4.URNObject.__init__(self, urn)
        self.properties = {}
        self.urn = urn
        global NEW_OBJECTS
        NEW_OBJECTS.append(self)
        
        dbh = DB.DBO()
        dbh.execute("select * from AFF4_urn where urn = %r", urn)
        row = dbh.fetch()
        if row:
            self.urn_id = row['urn_id']
        else:
            dbh.insert("AFF4_urn", _fast=True,
                       urn = urn)
            self.urn_id = dbh.autoincrement()

    def add(self, attribute, value):
        attribute_id = get_attribute_id(attribute)
        dbh = DB.DBO()
        dbh.insert("AFF4", _fast=True,
                   urn_id = self.urn_id,
                   attribute_id = attribute_id,
                   value = value)

    def delete(self, attribute):
        attribute_id = get_attribute_id(attribute)
        dbh = DB.DBO()
        dbh.delete("AFF4", _fast=True,
                   where = "attribute_id = %s and urn_id = %s" % (
            attribute_id,self.urn_id))

    def set(self, attribute, value):
        self.delete(attribute)
        self.add(attribute, value)

    def __getitem__(self, attribute):
        dbh = DB.DBO()
        attribute_id = get_attribute_id(attribute)
        dbh.execute("select value from AFF4 where attribute_id = %r and urn_id = %r",
                    (attribute_id, self.urn_id))
        result = [ x['value'] for x in dbh ]
        if result:
            return result
        else:
            return aff4.NoneObject("URN %s has no attribute %s" % (self.urn, attribute))

    def export(self):
        result = ''
        dbh = DB.DBO()
        dbh.execute("select attribute, value from AFF4_attribute join AFF4 on AFF4_attribute.attribute_id = AFF4.attribute_id where AFF4.urn_id = %r group by urn_id, AFF4.attribute_id, value", self.urn_id)
        for row in dbh:
            if not row['attribute'].startswith(VOLATILE_NS):
                result += "       %s = %s\n" % (row['attribute'], row['value'])

        return result

    def flush(self, case=None):
        """ Write ourselves to the DB """
        return
        if not self.properties: return
        
        if not case: pdb.set_trace()
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
                PDBO.insert("AFF4", _fast=True,
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

    def create(self, dbh, case):
        """ Create a new case AFF4 Result file """
        volume = aff4.ZipVolume(None, 'w')
        filename = "file://%s/%s.aff4" % (config.RESULTDIR, case)
        aff4.oracle.set(volume.urn, aff4.AFF4_STORED, filename)
        volume.finish()
        aff4.oracle.cache_return(volume)
            
    def startup(self):
        dbh = DB.DBO()
        try:
            dbh.execute("desc AFF4")
        except: self.init_default_db(dbh, None)
        
## FIXME - move to Core.py
from pyflag.ColumnTypes import StringType, TimestampType, AFF4URN, FilenameType, IntegerType, DeletedType, SetType, BigIntegerType, StateType

class ThumbnailType(AFF4URN):
    """ A Column showing thumbnails of inodes """
    def __init__(self, name='Thumbnail', **args ):
        AFF4URN.__init__(self, name, **args)
        self.fsfd = FileSystem.DBFS(self.case)
        self.name = name
        
    def select(self):
        return "%s.inode_id" % self.table

    ## When exporting to html we need to export the thumbnail too:
    def render_html(self, inode_id, table_renderer):
        ct=''
        try:
            fd = self.fsfd.open(inode_id = inode_id)
            image = Graph.Thumbnailer(fd, 200)
            inode_filename, ct, fd = table_renderer.make_archive_filename(inode_id)

            filename, ct, fd = table_renderer.make_archive_filename(inode_id, directory = "thumbnails/")
        
            table_renderer.add_file_from_string(filename,
                                                image.display())
        except IOError,e:
            print e
            return "<a href=%r ><img src='images/broken.png' /></a>" % inode_filename

        AFF4URN.render_html(self, inode_id, table_renderer)
        table_renderer.add_file_to_archive(inode_id)
        return DB.expand("<a href=%r type=%r ><img src=%r /></a>",
                         (inode_filename, ct, filename))

    def render_thumbnail_hook(self, inode_id, row, result):
        try:
            fd = self.fsfd.open(inode_id=inode_id)
            image = PIL.Image.open(fd)
        except IOError,e:
            tmp = result.__class__(result)
            tmp.icon("broken.png")
            return result.row(tmp, colspan=5)

        width, height = image.size

        ## Calculate the new width and height:
        new_width = 200
        new_height = int(float(new_width) / width * height)

        if new_width > width and new_height > height:
            new_height = height
            new_width = width

        def show_image(query, result):
            ## Try to fetch the cached copy:
            filename = "thumb_%s" % inode_id

            try:
                fd = CacheManager.MANAGER.open(self.case, filename)
                thumbnail = fd.read()
            except IOError:
                fd = self.fsfd.open(inode_id=inode_id)
                fd = cStringIO.StringIO(fd.read(2000000) + "\xff\xd9")
                image = PIL.Image.open(fd)
                image = image.convert('RGB')
                thumbnail = cStringIO.StringIO()

                try:
                    image.thumbnail((new_width, new_height), PIL.Image.NEAREST)
                    image.save(thumbnail, 'jpeg')
                    thumbnail = thumbnail.getvalue()
                except IOError,e:
                    print "PIL Error: %s" % e
                    thumbnail = open("%s/no.png" % (config.IMAGEDIR,),'rb').read()

                CacheManager.MANAGER.create_cache_from_data(self.case, filename, thumbnail)
                fd = CacheManager.MANAGER.open(self.case, filename)
                
            result.result = thumbnail
            result.content_type = 'image/jpeg'
            result.decoration = 'raw'

        
        result.result += "<img width=%s height=%s src='f?callback_stored=%s' />" % (new_width, new_height,
                                                                result.store_callback(show_image))

    display_hooks = AFF4URN.display_hooks[:] + [render_thumbnail_hook,]

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
#    test_file = 'pcap.zip'
    test_file = '/testimages/pyflag_stdimage_0.5.e01'

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
                                 argv=['*', 'TypeScan', 'PartitionScanner',
                                       'FilesystemLoader'])
            
        fd = CacheManager.AFF4_MANAGER.create_cache_fd(self.test_case, "/foo/bar/test.txt")
        fd.write("hello world")
        fd.close()


import atexit

def close_off_volume():
    """ Check for dirty volumes are closes them """
    dbh = DB.DBO()
    dbh.execute("select value from meta where property='flag_db'")
    for row in dbh:
        volume_urn = CacheManager.AFF4_MANAGER.make_volume_urn(row['value'])
        if aff4.oracle.resolve(volume_urn, AFF4_VOLATILE_DIRTY):
            fd = aff4.oracle.open(volume_urn, 'w')
            if fd:
                fd.close()

atexit.register(close_off_volume)
