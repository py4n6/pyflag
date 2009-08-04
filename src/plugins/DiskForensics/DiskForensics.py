# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
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

""" Flag module for performing structured disk forensics """
import pyflag.Reports as Reports
from pyflag.FlagFramework import Curry,query_type
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()
import os,os.path,time,re, cStringIO
import pyflag.FileSystem as FileSystem
import pyflag.Graph as Graph
import pyflag.IO as IO
import pyflag.DB as DB
import pyflag.Scanner as Scanner
import pyflag.ScannerUtils as ScannerUtils
import pyflag.Registry as Registry
import pyflag.parser as parser
from pyflag.ColumnTypes import IntegerType,TimestampType,FilenameType, StringType, StateType
from pyflag.ColumnTypes import DeletedType, BinaryType

class BrowseFS(Reports.CaseTableReports):
    """
    Browsing the FileSystem
    -----------------------

    The Virtual Filesystem is a central concept to PyFlag's
    operation. This report allows users to browse through the
    filesystem in a natural way.

    The report presents two views:

    - A Tree View:

       Allows for the perusal of files and directories in a tree hirarchy.

    - A Table View:

       This presents the list of files within the VFS in a tabular
       fasion. It is them possible to search through the list simply
       by introducing filter conditions.


    """
    hidden = False
    order=5
    name = "Browse Filesystem"
    family = "Disk Forensics"
    description = "Display filesystem in a browsable format"
    default_table = "AFF4VFS"
    
    def display(self,query,result):
        result.heading("Browsing Virtual Filesystem")
        def tabular_view(query,result):
            self.make_table_widget(['URN', 'Filename',
                                    'Size', 'Modified'],
                                   query, result)

        def tree_view(query,result):
            def tree_cb(path):
                fsfd = FileSystem.DBFS(query["case"])

                for i in fsfd.longls(path):
                    if i['type'] == 'directory':
                        yield(([i['name'],i['name'],'branch']))

            def pane_cb(path,result):
                query['order']='Filename'
                if path=='': path='/'
                
                ## If we are asked to show a file, we will show the
                ## contents of the directory the file is in:
                fsfd = FileSystem.DBFS( query["case"])
                if not fsfd.isdir(path):
                    path=os.path.dirname(path)

                self.make_table_widget(['URN','Name',
                                        'Size','Modified'],
                                       query, result,
                                       where=DB.expand("path=%r and (isnull(type) or type!='directory')", (path)),)
                
                result.toolbar(text=DB.expand("Scan %s",path),
                               icon="examine.png",
                               link=query_type(family="Load Data", report="ScanFS",
                                               path=path,
                                               case=query['case']), pane='popup'
                               )
    
            result.tree(tree_cb = tree_cb,pane_cb = pane_cb)
        
        result.notebook(
            names=["Tree View","Table View"],
            callbacks=[tree_view,tabular_view],
            )

    def form(self,query,result):
        result.case_selector()

class ViewFile(Reports.report):
    """ Report to browse the filesystem """
    parameters = {'inode_id':'numeric'}
    family = "Disk Forensics"
    name = "View File Contents"
    description = "Display the contents of a file"
    
    def display(self,query,result):
        new_q = result.make_link(query, '')
        if not query.has_key('limit'): query['limit']= 0
        dbh = self.DBO(query['case'])

        fsfd = FileSystem.DBFS(query["case"])
        ## If this is a directory, only show the stats
        fd = fsfd.open(inode_id=query['inode_id'])
        if not fd: return

        tmp = result.__class__(result)
        tmp.text(fd.urn)
        result.heading(tmp)
        
#         try:
#             result.text("Classified as %s by magic" % )
#         except IOError,e:
#             result.text("Unable to classify file, no blocks: %s" % e)
#             image = None
#         except:
#             pass

        names, callbacks = fd.make_tabs()
        
        result.notebook(
            names=names,
            callbacks=callbacks,
            context="mode"
            )
        
        result.toolbar(text="Scan this File",icon="examine.png",
                       link=query_type(family="Load Data", report="ScanInode",
                                       inode_id = query['inode_id'],
                                       case=query['case']
                                       ),
                       pane = 'pane'
                       )

    def form(self,query,result):
        result.case_selector()
        result.textfield('URN','urn')
        return result

