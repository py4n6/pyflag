# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ******************************************************
""" This scanner scans a file for its mime type and magic """
import pyflag.FlagFramework as FlagFramework
import pyflag.CacheManager as CacheManager
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FileSystem as FileSystem
import pyflag.DB as DB
import PIL, cStringIO, PIL.ImageFile
import PIL.Image as Image
import os.path
import pyflag.Scanner as Scanner
import pyflag.Reports as Reports
import pyflag.Graph as Graph
import pyflag.IO as IO
import pyflag.Registry as Registry
from pyflag.ColumnTypes import StringType, TimestampType,AFF4URN, FilenameType, IntegerType
import fnmatch
import pyflag.Magic as Magic

class TypeScan(Scanner.GenScanFactory):
    """ Detect File Type (magic). """
    order=5
    default=True
    group = "FileScanners"

    def multiple_inode_reset(self,inode_id):
        Scanner.GenScanFactory.multiple_inode_reset(self, inode_id)
        dbh=DB.DBO(self.case)
        dbh.execute("delete from `type` where inode_id = %r )", inode_id)

    def reset(self,inode_id):
        Scanner.GenScanFactory.reset(self, inode_id)
        dbh=DB.DBO(self.case)
        dbh.execute("delete from `type` where inode_id = %r limit 1)" , inode)

    def reset_entire_path(self, path_glob):
        path = path_glob
        if not path.endswith("*"): path = path + "*"  
        db = DB.DBO(self.case)
        db.execute("delete from type where inode_id in (select inode_id from vfs where path rlike %r)", fnmatch.translate(path))
        Scanner.GenScanFactory.reset_entire_path(self, path_glob)
        
    def destroy(self):
        pass

    class Scan(Scanner.BaseScanner):
        type_str = None
        
        def process(self, data, metadata=None):
            if self.type_str==None:
                m = Magic.MagicResolver()
                self.type_str, self.type_mime = m.cache_type(self.case, self.fd.inode_id, data[:1024])
                metadata['mime'] = self.type_mime
                metadata['type'] = self.type_str
                
## A report to examine the Types of different files:
class ViewFileTypes(Reports.CaseTableReports):
    """ Browse the file types discovered.

    This shows all the files in the filesystem with their file types as detected by magic. By searching and grouping for certain file types it is possible narrow down only files of interest.

    A thumbnail of the file is also shown for rapid previewing of images etc.
    """
    name = "Browse Types"
    family = "Disk Forensics"
    default_table = 'AFF4VFS'
    description = "Display the type table"
    columns = [ "Thumb", "Name", "TypeCaseTable.Type",
                "Size", "Modified"]

## Show some stats:
import pyflag.Stats as Stats
class MimeTypeStats(Stats.Handler):
    name = "Mime Types"

    def render_tree(self, branch, query):
        dbh = DB.DBO(self.case)
        ## Top level view - we only show the File Types stats branch
        ## if we have any types there.
        if not branch[0]:
            dbh.execute("select count(*) as a from type")
            row = dbh.fetch()
            if row['a']>0:
                yield (self.name, self.name, 'branch')
        elif branch[0] != self.name:
            return
        elif len(branch)==1:
            dbh.execute("select `type`.`mime`  from `type` group by `mime`")
            for row in dbh:
                t = row['mime'][:20]
                yield (row['mime'].replace("/","__"), t, 'leaf')

    def render_pane(self, branch, query, result):
        ## We may only draw on the pane that belongs to us:
        if branch[0] != self.name:
            return

        if len(branch)==1:
            result.heading("Show file types")
            result.text("This statistic allows different file types to be examined")
        else:
            t = branch[1].replace("__",'/')
            result.table(
                elements = [ AFF4URN(case = self.case),
                             FilenameType(case = self.case, link_pane='main'),
                             IntegerType('Size','size', table='vfs'),
                             TimestampType('Timestamp','mtime', table='vfs'),
                             StringType('Type', 'type', table='type'),
                             ],
                table = 'type',
                where = DB.expand('type.mime=%r ', t),
                case = self.case,
                )

class TypeStats(Stats.Handler):
    name = "File Types"

    def render_tree(self, branch, query):
        dbh = DB.DBO(self.case)
        ## Top level view - we only show the File Types stats branch
        ## if we have any types there.
        if not branch[0]:
            dbh.execute("select count(*) as a from type")
            row = dbh.fetch()
            if row['a']>0:
                yield (self.name, self.name, 'branch')
        elif branch[0] != self.name:
            return
        elif len(branch)==1:
            dbh.execute("select `type`.`type`  from `type` group by `type`")
            for row in dbh:
                t = row['type'][:20]
                yield (row['type'].replace("/","__"), t, 'leaf')

    def render_pane(self, branch, query, result):
        ## We may only draw on the pane that belongs to us:
        if branch[0] != self.name:
            return

        if len(branch)==1:
            result.heading("Show file types")
            result.text("This statistic allows different file types to be examined")
        else:
            t = branch[1].replace("__",'/')
            result.table(
                elements = [ AFF4URN(case = self.case),
                             FilenameType(case = self.case, link_pane='main'),
                             IntegerType('Size','size', table='vfs'),
                             TimestampType('Timestamp','mtime', table='vfs'),
                             StringType('Mime', 'mime', table='type')],
                table = 'type',
                where = DB.expand('type.type=%r ', t),
                case = self.case,
                )
                
## UnitTests:
import unittest
import pyflag.pyflagsh as pyflagsh
import pyflag.tests

class TypeTest(pyflag.tests.ScannerTest):
    """ Magic related Scanner """
    test_case = "PyFlagTestCase"
    test_file = "pyflag_stdimage_0.5.e01"
    subsystem = 'EWF'
    offset = "16128s"

    def test01TypeScan(self):
        """ Check the type scanner works """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'TypeScan'])

        ## Make sure the extra magic is being used properly.
        dbh = DB.DBO(self.test_case)
        dbh.execute('select count(*) as count from type where type like "%%Outlook%%"')
        count = dbh.fetch()['count']
        self.failIf(count==0, "Unable to locate an Outlook PST file - maybe we are not using our custom magic file?")

def operator_has_magic(self, column, operator, magic):
    """ Matches those inodes which match certain magic strings. Note that the TypeScanner must have been run on these inodes first """
    return "( %s in (select inode_id from type where type like '%%%s%%'))" % \
           (self.escape_column_name(self.column), magic)

AFF4URN.operator_has_magic = operator_has_magic

class TypeCaseTable(FlagFramework.CaseTable):
    """ Type Table """
    name = 'type'
    columns = [ [ AFF4URN, {}],
                [ StringType, dict(name = 'Mime', column = 'mime')],
                [ StringType, dict(name = 'Type', column = 'type')],
                ]
    index = [ 'type', ]
