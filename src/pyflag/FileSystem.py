#!/usr/bin/env python
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

""" Module contains classes used to access filesystems loaded into the database.

When Flag loads a filesystem into the database, meta information about inodes, files and their allocation is stored within the database. The specific implementation of how this information is stored is abstracted here by use of the FileSystem object. The FileSystem object presents a well defined API to allow callers to query the case database about the filesystem.

The FileSystem class is an abstract class which is implemented as derived classes. FileSystems implement this abstract class in plugins which are then registered in the registry. Users of this class need to use the registry to get specific implementations. The implementation deals with representing the directory structure, and provides access to the files within the filesystem.

The File class abstracts an interface for accessing the data within a specific file inside the filesystem. Although this is very similar to the standard python file-like interface, there are some minor differences.

In order for callers to have access to a specific file on the filesystem, they need to instantiate a FileSystem object by using the Registry, and then ask this instance for a File object by using the FileSystem.open method. It is discouraged to instantiate a File object directly.

Virtual Filesystems (vfs) are also supported by this subsystem in order to support archives such as zip and pst files. Files within filesystems are uniquely identified in the flag databases by an inode string. The inode string can have multiple parts delimited by the pipe ('|') character indicating that a virtual filesystem is to be used on the file. The first letter in the part indicates the virtual filesystem to use, here is an example:
'D123|Z14' Here 'D' indicates the DBFS filesystem, Z indicates the Zip vfs.
This inode therefore refers to the 14th file in the zip archive contained in inode 123 of the DBFS filesystem. VFS modules are also obtained using the registry.

Note that typically VFS modules go hand in hand with scanners, since scanner discover new files, calling VFSCreate on the filesystem to add them, and VFS drivers are used to read those from the Inode specifications.
"""
import os,os.path, fnmatch, posixpath
import sys, pdb
import pyflag.conf
config=pyflag.conf.ConfObject()

import pyflag.DB as DB
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework
from pyflag.FlagFramework import normpath
import pyflag.Registry as Registry
import pyflag.pyflaglog as pyflaglog
import time,re
import math
import bisect
import zipfile
import StringIO
import pyflag.Scanner as Scanner
import pyflag.Store as Store
import pyflag.CacheManager as CacheManager
from pyflag.aff4.aff4_attributes import *
import pyflag.aff4.aff4 as aff4

class File:
    """ This is a proxy object to the underlying AFF4 stream object.
    """
    specifier = None
    ignore = False
    overread = False
    
    def __init__(self, case, inode_id=None, urn=None):
        self.case = case
        dbh = DB.DBO()

        if urn:
            self.urn = urn
            dbh.execute("select urn_id from AFF4_urn where urn = %r", urn)
            self.inode_id = dbh.fetch()['urn_id']
        else:
            dbh.execute("select urn from AFF4_urn where urn_id = %r", inode_id)
            row = dbh.fetch() 
            self.urn = row['urn']
            self.inode_id = inode_id
            
        self.size = int(aff4.oracle.resolve(self.urn, AFF4_SIZE))
        self.readptr = 0
        
        # should reads return slack space or overread into the next block? 
        # NOTE: not all drivers implement this (only really Sleuthkit)
        self.slack = False
        self.overread = False

    def close(self):
        pass

    def __getitem__(self, item):
        return aff4.oracle.resolve(self.urn, item)
    
    def seek(self, offset, rel=None):
        """ Seeks to a specified position inside the file """
        ## If the file is cached we seek the backing file:
        if rel==1:
            self.readptr += offset

        ## Seek relative to size
        elif rel==2:
            self.readptr = self.size + offset
        else:
            self.readptr = offset

        ## FIXME - implement overread.
            
        if self.readptr<0:
            raise IOError("Invalid Arguement")

        return self.readptr
         
    def tell(self):
        """ returns the current read pointer"""
        return self.readptr

    def read(self, length=None):
        """ Reads length bytes from file, or less if there are less
        bytes in file. If length is None, returns the whole file"""
        if length is None:
            length = self.size - self.readptr

        fd = aff4.oracle.open(self.urn, 'r')
        try:
            fd.seek(self.readptr)
            result = fd.read(length)
        finally:
            aff4.oracle.cache_return(fd)

        self.readptr+=len(result)
        return result
            
    def stat(self):
        """ Returns a dict of statistics about the content of the file. """
        urn_obj = aff4.oracle[self.urn]
            
        result = urn_obj.properties.copy()

        dbh = DB.DBO(self.case)
        dbh.execute("select * from vfs where inode_id = %r", self.inode_id)
        row = dbh.fetch()
        if row: result.update(row)
        
        return result

    def gettz(self):
        """ return the original evidence timezone of this file """
        pass
    
    def __iter__(self):
        self.seek(0)
        return self

    def next(self):
        data=self.read(1024*1024)
        if len(data)!=0:
            return data
        else:
            raise StopIteration

    def make_tabs(self):
        """ A callback to render the tabs view in the View Inode report """
        try:
            names, cbs = self.fd.make_tabs()
        except  AttributeError:
            names = []
        
        stat_names = ["Statistics","HexDump", "TextDump", "Download","Summary", "Explain"]
        stat_cbs =   [self.stats,
                      self.hexdump,
                      self.textdump,
                      self.download,
                      self.summary,
                      self.explain]

        ## Can our baseclass add anything?
        for i in range(len(names)):
            if names[i] not in stat_names:
                stat_names.append(names[i])
                stat_cbs.append(cbs[i])
        
        return stat_names, stat_cbs

    def readline(self,delimiter='\n'):
        """ Emulates a readline by reading upto the \n """
        buffer = ''
        start = self.tell()
        while 1:
            try:
                o = buffer.index(delimiter)+1
                self.seek(start+o)
                return buffer[:o]
            except ValueError:
                data=self.read(256)
                if len(data)==0: return buffer
                buffer += data


    def explain(self, query, result):
        """ This method is called to explain how we arrive at this
        data"""
        fd = aff4.oracle.open(self.urn, 'r')
        try:
            result.text(fd.explain(), font='typewriter')
        finally:
            aff4.oracle.cache_return(fd)

    def summary(self, query,result):
        """ This method draws a summary of the file.

        We basically hand off all processing to the ViewFile report -
        we just store it here in an iframe.
        """
        new_query = FlagFramework.query_type(family ="Network Forensics",
                                             report ="ViewFile",
                                             case   =query['case'],
                                             inode_id    = self.inode_id)
        
        result.result = "<iframe id='summaryFrame' name='summaryFrame' height='100%%' width='100%%' src='f?%s'></iframe><script>AdjustHeightToPageSize('summaryFrame');</script>" % new_query
        
    def download(self, query,result):
        """ Used for dumping the entire file into the browser """
        result.download(self)

    def textdump(self, query,result):
        max=config.MAX_DATA_DUMP_SIZE
        pdb.set_trace()

        def textdumper(offset, data,result):
            result.text(data, font='typewriter', sanitise='full', wrap='full', style='red',
                        max_lines = 500)
        
        return self.display_data(query,result, max, textdumper)

    def hexdump(self, query,result):
        """ Show the hexdump for the file."""
        match=0
        length=0
        try:
            match=int(query['highlight'])
            length=int(query['length'])
        except:
            pass

        max=config.MAX_DATA_DUMP_SIZE

        def hexdumper(offset,data,result):
            dump = FlagFramework.HexDump(data,result)
            # highlighting (default highlight)
            highlight = [[0, sys.maxint, 'alloc'],]
            # if we know size, highlight slack/overread
            if self.size:
                highlight.append([self.size-offset, sys.maxint, 'slack'])
                try:
                    slacksize = self.size % self.block_size
                    if(slacksize):
                        slacksize = self.block_size - slacksize
                    highlight.append([self.size + slacksize - offset, sys.maxint, 'overread'])
                except AttributeError:
                    pass
            # now highlight any matches
            highlight.append([match-offset, length, 'match'])
            dump.dump(base_offset=offset,limit=max,highlight=highlight)

        return self.display_data(query,result, max, hexdumper, slack=True, overread=True)

    def display_data(self, query,result,max,cb, slack=False, overread=False):
        """ Displays the data.
        
        The callback takes care of paging the data from self. The callback cb is used to actually render the data:
        
        'def cb(offset,data,result)
        
        offset is the offset in the file where we start, data is the data.
        """
        #Set limits for the dump
        try:
            limit=int(query['hexlimit'])
        except KeyError:
            limit=0
            
        oldslack = self.slack
        oldoverread = self.overread
        self.slack = slack
        self.overread = overread

        self.seek(limit)
        data = self.read(max+1)

        self.slack = oldslack
        self.overread = oldoverread

        ## We try to use our own private toolbar if possible:
        #toolbar_id = result.new_toolbar()
        toolbar_id = 1
        
        if (not data or len(data)==0):
            result.text("No Data Available")
        else: 
            cb(limit,data,result)

        #Do the navbar
        new_query = query.clone()
        previous=limit-max
        if previous<0:
            if limit>0:
                previous = 0
            else:
                previous=None

        if previous != None:        
            new_query.set('hexlimit',0)
            result.toolbar(text="Start", icon="stock_first.png",
                           link = new_query, toolbar=toolbar_id , pane="self")
        else:
            result.toolbar(text="Start", icon="stock_first_gray.png", toolbar=toolbar_id, pane="self")
            
        if previous != None:
            new_query.set('hexlimit',previous)
            result.toolbar(text="Previous page", icon="stock_left.png",
                           link = new_query, toolbar=toolbar_id , pane="self")
        else:
            result.toolbar(text="Previous page", icon="stock_left_gray.png", toolbar=toolbar_id, pane="self")

        next=limit + max
            
        ## If we did not read a full page, we do not display
        ## the next arrow
        if len(data)>=max:
            new_query.set('hexlimit',next)
            result.toolbar(text="Next page", icon="stock_right.png",
                           link = new_query , toolbar=toolbar_id, pane="self")
        else:
            result.toolbar(text="Next page", icon="stock_right_gray.png", toolbar=toolbar_id, pane="self")

        if len(data)>=max:
            new_query.set('hexlimit',self.size - self.size % 1024)
            result.toolbar(text="End", icon="stock_last.png",
                           link = new_query , toolbar=toolbar_id, pane="self")
        else:
            result.toolbar(text="End", icon="stock_last_gray.png", toolbar=toolbar_id, pane="self")

        ## Allow the user to skip to a certain page directly:
        result.toolbar(
            cb = FlagFramework.Curry(goto_page_cb, variable='hexlimit'),
            text="Current Offset %s" % limit,
            icon="stock_next-page.png", toolbar=toolbar_id, pane="popup"
            )

        return result

    def stats(self, query,result, merge = None):
        """ Show statistics about the file """
        fsfd = DBFS(query['case'])
        istat = fsfd.istat(inode_id=query['inode_id'])
        left = result.__class__(result)
        link = result.__class__(result)

        link.link(self.urn,
                  FlagFramework.query_type((),family="Disk Forensics",
                      report='BrowseFS',
                      open_tree=self.urn, case=query['case'])
                  )
        left.row("Filename:",'',link)
        if merge:
            istat.update(merge)
            
        try:
            for k,values in istat.items():
                for v in values:
                    left.row('%s:' % k,'',v, align='left')
        except AttributeError:
            pass

        left.end_table()

        result.start_table(width="100%")
        result.row(left,valign='top',align="left")

class FileSystem:
    """ This is the base class for accessing file systems in PyFlag. This class is abstract and is here purely for documentation purposes.

    @cvar name: The name of the filesystem to show in the loadfs dialog
    """
    ## This is the cookie which will be used to identify scanning jobs
    ## from this FS:
    cookie = 0
    
    def __init__(self, case, query=None):
        """ Constructor for creating an new filesystem object

        @arg case: Case to use
        @arg iosource: An already open data source, may be iosource, or another 'File'
        """
        pass
    
    name = None
    
    def load(self, mount_point, iosource_name, scanners=None):
        """ This method loads the filesystem into the database.

        Currently the database schema is standardised by the DBFS
        class, and all other filesystems just extend the load method
        to implement different drivers for loading the filesystem into
        the database. For reading and manipulating the filesystem, the
        DBFS methods are used.

        scanners contains a list of scanner names which will be scheduled to run on every newly created VFS node.
        
        """
        pass

    def delete(self):
        """ This method should remove the database which contains the filesystem """
        pass
    
    def longls(self,path='/'):
        """ list directory content longly """
        pass

    def VFSCreate(self,root_inode,inode, _fast=False, link=None, inode_id=None):
        """ This method creates inodes within the virtual filesystem.

        This facility allows callers to extend the VFS to include more virtual files.
        """

    def ls(self, path="/", dirs=None):
        """list directory contents"""
        pass

    def dent_walk(self, path='/'):
        """A generator which returns directory entries under the given path, one at a time """
        pass

    def lookup(self, path=None,inode=None):
        """return the inode number for the given path, or else the path for the given inode number. """
        pass

    def open(self, inode_id=None, urn=None):
        """ Opens the specified path or Inode providing a file like object.

        This object can then be used to read data from the specified file.
        @note: Only files may be opened, not directories."""
        return File(self.case, inode_id, urn)

    def istat(self, inode_id):
        """ return a dict with information (istat) for the given inode or path. """
        pass

    def isdir(self,directory):
        """ Returns 1 if directory is a directory, 0 otherwise """
        pass

    def exists(self,path):
        """ Returns 1 if path exists, 0 otherwise """
        pass

    def resetscanfs(self,callbacks):
        """ This is called to reset all the scanners. """
        
    def scanfs(self, callbacks):
        """ Read every file in fs, and call given scanner callbacks for each file.
        
        callbacks is a list of scanner classes derived from Scanner.GenScan. These classes
        have a process and finish methods.
        For each file, scanfs will create a new object of each of the given classes,
        then begin reading the file in buffers of (say) 1MB, each time calling the 
        process method of each of the new objects with the buffer just read.
        When all data has been read from the file, scanfs will call the finished method of each object.
        It will then start over with the next file.
        
        The purpose of this method is to do all analysis which must read file data in one place
        for performance, currently this includes file typing, file hashing and virus scanning"""
        pass

    def guess(self, fd, result, metadata):
        """ Uses fd to guess how suitable this filesystem driver is for this image """
        if not "magic" in metadata:
            fd.seek(0)
            data = fd.read(10240)
            if data:
                import pyflag.Magic as Magic
                magic = Magic.MagicResolver()
                result.ruler()
                sig, ct = magic.get_type(data)
                result.row("Magic identifies this file as: %s" % sig,**{'colspan':50,'class':'hilight'})
                fd.close()
                metadata['magic'] = sig
            else:
                metadata['magic'] = ''
        
        return 10

    def lstat(self,path):
        """ standards compliant 'stat' returns a stat_result """
        pass

    def readlink(self,path):
        """ return value of a symbolic link """
        pass

    def listdir(self,path):
        """ standards compliant listdir, generates directory entries. """
        return self.ls(path)

    ## These are the list of parameters which we need to fulfil for
    ## this filesystem
    parameters = []
    def form(self, query, result):
        """ We are able to ask for more optional variables here """
    
# class DBFS_old(FileSystem):
#     """ Class for accessing filesystems using data in the database """
#     def __init__(self, case, query=None):
#         """ Initialise the DBFS object """
#         self.case = case
#         ## This allows us to get optional args
#         self.query = query

#     def load(self, mount_point, iosource_name, loading_scanners = None):
#         """ Sets up the schema for loading the filesystem.

#         Note that derived classes need to actually do the loading
#         after they call the base class.

#         loading_scanners are the scanners which need to be run on
#         every new Inode.
#         """
#         self.mount_point = mount_point
#         dbh=DB.DBO(self.case)
        
#         ## Commented out to fix Bug0035. This should be (and is) done
#         ## by VFSCreate, since we want to avoid duplicate mount
#         ## points.  mic: This is here because skfs.load does not use
#         ## VFSCreate for speed reasons and therefore does not
#         ## necessarily create the mount points when needed.  Ensure
#         ## the VFS contains the mount point:
#         self.VFSCreate(None, "I%s" % iosource_name, mount_point, 
#                        directory=True)

#         dbh.insert("filesystems",
#                    iosource = iosource_name,
#                    property = 'mount point',
#                    value = mount_point)
        
#         ## Ensure that we have the IOSource available
#         self.iosource = IO.open(self.case, iosource_name)

#     def VFSRename(self, inode_id, filename):
#         """ Renames the inode to a new filename (moves it in the VFS) """
#         dirname, basename = os.path.split(filename)
#         dbh = DB.DBO(self.case)
#         dbh.update('file', where='inode_id = %s' % inode_id,
#                    path = dirname+'/', name = basename)

#     def VFSCreate(self,root_inode,inode,new_filename,directory=False ,gid=0, uid=0, mode=100777,
#                   _fast=False, inode_id=None, update_only=False,
#                   **properties):
#         ## Basically this is how this function works - if root_inode
#         ## is provided we make the new inode inherit the root inodes
#         ## path and inode string.
#         pyflaglog.log(pyflaglog.VERBOSE_DEBUG, DB.expand("Creating new VFS node %s at %s", (inode, new_filename)))
#         if root_inode:
#             try:
#                 path, root_inode, tmp_inode_id = self.lookup(inode = root_inode)
#                 new_filename = path + "/" + new_filename
#             except:
#                 new_filename = "/"+new_filename
#             inode = "%s|%s" % (root_inode,inode)

#         if directory:
#             directory_string = "d/d"
#         else:
#             directory_string = "r/r"

#         ## Normalise the path:
#         dbh = DB.DBO(self.case)
#         dbh.check_index('file','path', 200)
#         dbh.check_index('file','name', 200)

#         if new_filename:
#             new_filename=posixpath.normpath(new_filename)

#             ## Make sure that all intermediate dirs exist:
#             dirs = posixpath.dirname(new_filename).split("/")
#             for d in range(len(dirs)-1,0,-1):
#                 path = "/".join(dirs[:d])+"/"
#                 path = FlagFramework.normpath(path)
#                 dbh.execute("select * from file where path=%r and name=%r and mode='d/d' limit 1",(path, dirs[d]))
#                 if not dbh.fetch():
#                     dbh.execute("insert into file set inode='',path=%r,name=%r,status='alloc',mode='d/d'",(path,dirs[d]))
#                 else: break

#         ## Fixes bug0035: directories get interpolated above and need
#         ## not be specifically inserted.
#         #if directory: return

#         inode_properties = dict(status="alloc", mode=40755, links=4, _fast=_fast,
#                                 size=0)
#         try:
#             inode_properties['mtime'] = self.mtime
#         except: pass
        
#         if inode:
#             inode_properties['inode'] = inode

#         if inode_id:
#             inode_properties['inode_id'] = inode_id
        
#         try:
#             inode_properties['size'] = int(properties['size'])
#         except KeyError:
#             pass

#         for t in ['ctime','atime','mtime']:
#             if properties.get("_"+t):
#                 inode_properties["_"+t] = "from_unixtime(%r)" % int(properties["_"+t])
#                 try:
#                     del inode_properties[t]
#                 except KeyError: pass
#             elif properties.get(t):
#                     inode_properties[t] = properties[t]

#         if inode_id and update_only:
#             dbh.update('inode', where="inode_id=%s" % inode_id,
#                        **inode_properties)
#         else:
#             dbh.insert('inode', **inode_properties)
#             inode_id = dbh.autoincrement()

#         if not new_filename:
#             return inode_id

#         ## Now add to the file and inode tables:
#         file_props = dict(path = FlagFramework.normpath(posixpath.dirname(new_filename)+"/"),
#                           name = posixpath.basename(new_filename),
#                           status = 'alloc',
#                           mode = directory_string,
#                           inode_id = inode_id,
#                           _fast = _fast)

#         if inode: file_props['inode'] = inode

#         try:
#             file_props['link'] = properties['link']
#         except KeyError:
#             pass

#         dbh.insert('file',**file_props)

#         return inode_id

#     def longls(self,path='/', dirs = None):
#         dbh=DB.DBO(self.case)
#         if self.isdir(path):
#             ## If we are listing a directory, we list the files inside the directory            
#             if not path.endswith('/'):
#                 path=path+'/'

#             where = DB.expand(" path=%r " ,path)
#         else:
#             ## We are listing the exact file specified:
#             where = DB.expand(" path=%r and name=%r", (
#                 FlagFramework.normpath(posixpath.dirname(path)+'/'),
#                 posixpath.basename(path)))
                   
#         mode =''
#         if(dirs == 1):
#             mode=" and file.mode like 'd%'"
#         elif(dirs == 0):
#             mode=" and file.mode like 'r%'"

#         dbh.execute("select * from file where %s %s", (where, mode))
#         result = [dent for dent in dbh]

#         for dent in result:
#             if dent['inode']:
#                 dbh.execute("select * from inode where inode = %r", dent['inode'])
#                 data = dbh.fetch()
#                 if data:
#                     dent.update(data)

#         return result
#         ## This is done rather than return the generator to ensure that self.dbh does not get interfered with...
#         ## result=[dent for dent in self.dbh]
#         ## return result
    
#     def ls(self, path="/", dirs=None):
#         return [ "%s" % (dent['name']) for dent in self.longls(path,dirs) ]

#     def dent_walk(self, path='/'):
#         dbh=DB.DBO(self.case)
#         dbh.check_index('file','path', 200)
#         dbh.execute("select name, mode, status from file where path=%r order by name" , ( path))
#         return [ row for row in dbh ]
#         #for i in self.dbh:
#         #    yield(i)

#     def lookup(self, path=None,inode=None, inode_id=None):
#         dbh=DB.DBO(self.case)
#         if path:
#             dir,name = posixpath.split(path)
#             if not name:
#                 dir,name = posixpath.split(path[:-1])
#             if dir == '/':
#                 dir = ''

#             dbh.check_index('file','path', 200)
#             dbh.check_index('file','name', 200)
#             dbh.execute("select inode,inode_id from file where path=%r and (name=%r or name=concat(%r,'/')) limit 1", (dir+'/',name,name))
#             res = dbh.fetch()
#             if not res:
#                 raise RuntimeError("VFS path not found %s/%s" % (dir,name))
#             return path, res["inode"], res['inode_id']
        
#         elif inode_id:
#             dbh.check_index('inode','inode_id')
#             dbh.execute("select mtime, inode.inode, concat(path,name) as path from inode left join file on inode.inode_id=file.inode_id where inode.inode_id=%r order by file.status limit 1", inode_id)
#             res = dbh.fetch()
#             if not res: raise IOError("Inode ID %s not found" % inode_id)
#             self.mtime = res['mtime']
#             return res['path'],res['inode'], inode_id

#         else:
#             dbh.check_index('file','inode')
#             dbh.execute("select inode.inode_id,concat(path,name) as path from file join inode on inode.inode_id = file.inode_id where inode.inode=%r order by file.status limit 1", inode)
#             res = dbh.fetch()
#             if not res:
#                 raise RuntimeError("VFS Inode %s not known" % inode)
#             return res["path"], inode, res['inode_id']
        
#     def istat(self, path=None, inode=None, inode_id=None):
#         dbh=DB.DBO(self.case)
#         if path:
#             path, inode, inode_id = self.lookup(path)
#         elif inode:
#             path, inode, inode_id = self.lookup(inode=inode)
            
#         if not inode_id:
#             return None

#         dbh.check_index('inode','inode')
#         dbh.execute("select inode_id, inode, status, uid, gid, mtime, atime, ctime, dtime, mode, links, link, size from inode where inode_id=%r limit 1",(inode_id))
#         row = dbh.fetch()
#         if not row:
#             return None

#         dbh.execute("select * from file where inode=%r order by mode limit 1", inode);
#         result = dbh.fetch()
#         if result:
#             row.update(result)
#         return row
        
#     def isdir(self,directory):
#         directory=posixpath.normpath(directory)
#         if directory=='/': return 1
        
#         dbh=DB.DBO(self.case)
#         dirname=FlagFramework.normpath(posixpath.dirname(directory)+'/')
#         dbh.check_index('file','path', 200)
#         dbh.check_index('file','name', 200)
#         dbh.execute("select mode from file where path=%r and name=%r and mode like 'd%%' limit 1",(dirname,posixpath.basename(directory)))
#         row=dbh.fetch()
#         if row:
#             return 1
#         else:
#             return 0
        
#     def exists(self,path):
#         dir,file=posixpath.split(path)
#         dbh=DB.DBO(self.case)
#         dbh.execute("select mode from file where path=%r and name=%r limit 1",(dir,file))
#         row=dbh.fetch()
#         if row:
#             return 1
#         else:
#             return 0

#     def resetscanfs(self,scanners):
#         for i in scanners:
#             try:
#                 i.reset()
#             except DB.DBError,e:
#                 pyflaglog.log(pyflaglog.ERRORS,"Could not reset Scanner %s: %s" % (i,e))
        
#     def scanfs(self, scanners, action=None):
#         ## Prepare the scanner factory for scanning:
#         for s in scanners:
#             s.prepare()
        
#         dbh2 = DB.DBO(self.case)
#         dbh3=DB.DBO(self.case)

#         dbh3.execute('select inode, concat(path,name) as filename from file where mode="r/r" and status="alloc"')
#         count=0
#         for row in dbh3:
#             # open file
#             count+=1
#             if not count % 100:
#                 pyflaglog.log(pyflaglog.INFO,"File (%s) is inode %s (%s)" % (count,row['inode'],row['filename']))
                
#             try:
#                 fd = self.open(inode=row['inode'])
#                 Scanner.scanfile(self,fd,scanners)
#                 fd.close()
#             except Exception,e:
#                 pyflaglog.log(pyflaglog.ERRORS,"%r: %s" % (e,e))
#                 continue
        
#         for c in scanners:
#             c.destroy()

#     def lstat(self,path):
#         """ standards compliant 'stat' returns a stat_result """
#         dbh=DB.DBO(self.case)
#         path, inode, inode_id = self.lookup(path)

#         if not inode_id:
#             return None

#         dbh.check_index('inode','inode')
#         dbh.execute("select inode_id, inode, uid, gid, unix_timestamp(mtime) as mtime, unix_timestamp(atime) as atime, unix_timestamp(ctime) as ctime, mode, links, size from inode where inode_id=%r limit 1",(inode_id))
#         result = dbh.fetch()
#         if not result:
#             return None

#         if self.isdir(path): 
#             result['mode'] = 16877
#         else:
#             result['mode'] = 33188

#         result = os.stat_result((result['mode'],1,0,result['links'] or 0,result['uid'] or 0,result['gid'] or 0,result['size'] or 0,result['atime'] or 0,result['mtime'] or 0,result['ctime'] or 0))

#         return result

#     def readlink(self,path):
#         """ return value of a symbolic link """
#         dbh=DB.DBO(self.case)
#         path, inode, inode_id = self.lookup(path)

#         if not inode_id:
#             return None

#         dbh.check_index('inode','inode')
#         dbh.execute("select link from inode where inode_id=%r limit 1",(inode_id))
#         row = dbh.fetch()
#         if not row:
#             return None
#         return row['link']

#     def listdir(self,path):
#         """ standards compliant listdir, generates directory entries. """
#         return self.ls(path)

class DBFS(FileSystem):
    """ A FileSystem using AFF4 as the arena for the VFS """
    def __init__(self, case, query=None):
        """ Initialise the DBFS object """
        self.case = case
        ## This allows us to get optional args
        self.query = query

    def load(self, mount_point, iosource_name, loading_scanners = None):
        """ Sets up the schema for loading the filesystem.

        Note that derived classes need to actually do the loading
        after they call the base class.

        loading_scanners are the scanners which need to be run on
        every new Inode.
        """
        self.mount_point = mount_point
        dbh=DB.DBO(self.case)
        
        dbh.insert("filesystems",
                   iosource = iosource_name,
                   property = 'mount point',
                   value = mount_point)

    def lookup(self, path=None, inode=None, inode_id=None):
        dbh=DB.DBO(self.case)
        if path:
            dir,name = posixpath.split(path)
            if not name:
                dir,name = posixpath.split(path[:-1])
            if dir == '/':
                dir = ''

            dbh.execute("select inode_id, urn from vfs join "
                        "pyflag.AFF4_urn on "
                        "pyflag.AFF4_urn.urn_id=vfs.inode_id "
                        "where path=%r and (name=%r or "
                        "name=concat(%r,'/')) limit 1", (dir+'/',name,name))
            res = dbh.fetch()
            if not res:
                raise RuntimeError("VFS path not found %s/%s" % (dir,name))
            return path, res["urn"], res['inode_id']
        
        elif inode_id:
            dbh.execute("select urn_id, urn, concat(path,name) as path from vfs join "
                        "pyflag.AFF4_urn on "
                        "pyflag.AFF4_urn.urn_id=vfs.inode_id "
                        "where vfs.inode_id=%r limit 1", inode_id)
            res = dbh.fetch()
            if not res: raise IOError("Inode ID %s not found" % inode_id)
            self.mtime = res['mtime']
            return res['path'],res['inode'], inode_id

        else:
            dbh.execute("select vfs.inode_id, concat(path,name) as path from vfs join"
                        "pyflag.AFF4_urn on "
                        "pyflag.AFF4_urn.urn_id=vfs.inode_id "
                        "where urn=%r limit 1", inode)
            res = dbh.fetch()
            if not res:
                raise RuntimeError("VFS Inode %s not known" % inode)
            return res["path"], inode, res['inode_id']

        
    def VFSCreate(self,urn, path, directory=False,
                  _fast=False, inode_id=None,
                  status='alloc', timestamp=0,
                  **properties):
        """ Creates a new Inode in the VFS from AFF4 urn provided.

        The URN must already exist.
        """
        ## Basically this is how this function works - if root_inode
        ## is provided we make the new inode inherit the root inodes
        ## path and inode string.
        pyflaglog.log(pyflaglog.DEBUG,
                      DB.expand("Creating new VFS node %s", (urn)))

        ## Normalise the path:
        dbh = DB.DBO(self.case)
        new_filename=posixpath.normpath(path)

        ## Make sure that all intermediate dirs exist:
        dirs = posixpath.dirname(new_filename).split("/")
        for d in range(len(dirs),0,-1):
            new_path = FlagFramework.normpath("/".join(dirs[:d]))
            dirname = posixpath.dirname(new_path)
            basename = posixpath.basename(new_path)
            dbh.execute("select * from vfs where path=%r and "
                        "name=%r and type='directory' limit 1",(dirname,basename))
            if not dbh.fetch():
                dbh.insert("vfs",
                           status=status,
                           type = 'directory',
                           path = dirname,
                           name = basename)
            else: break

        if directory: return

        if urn:
            inode_id = aff4.oracle[urn].urn_id

        if not inode_id: raise RuntimeError("No inode_id found for the urn %s" % urn)
        inode_properties = dict(status=status,
                                mode= aff4.oracle.resolve(urn, AFF4_MODE) or 40755,
                                inode_id = inode_id,
                                type='file',
                                mtime = aff4.oracle.resolve(urn, AFF4_MTIME) or \
                                        aff4.oracle.resolve(urn, AFF4_TIMESTAMP) or \
                                        timestamp,
                                atime = aff4.oracle.resolve(urn, AFF4_ATIME) or timestamp,
                                ctime = aff4.oracle.resolve(urn, AFF4_CTIME) or timestamp,
                                size = aff4.oracle.resolve(urn, AFF4_SIZE) or 0,
                                _fast=_fast,
                                path = FlagFramework.normpath(posixpath.dirname(path)),
                                name = posixpath.basename(path))

        for t in ['ctime','atime','mtime']:
            time = inode_properties.pop(t)
            if time:
                inode_properties["_"+t] = DB.expand("from_unixtime(%r)", time)

        ## Is it already present?
        dbh.execute("select inode_id from vfs where inode_id = %r", inode_id)
        if dbh.fetch():
            dbh.update('vfs', where='inode_id = "%s"' % inode_id,
                       **inode_properties)
        else:
            dbh.insert('vfs',**inode_properties)

        return inode_id

    def longls(self,path='/', dirs = None):
        dbh=DB.DBO(self.case)
        if self.isdir(path):
            ## If we are listing a directory, we list the files inside the directory            
            where = DB.expand(" path=%r " ,path)
        else:
            ## We are listing the exact file specified:
            where = DB.expand(" path=%r and name=%r", (
                FlagFramework.normpath(posixpath.dirname(path)),
                posixpath.basename(path)))
                   
        dbh.execute("select * from vfs where %s group by inode_id,path,name", (where))
        result = [dent for dent in dbh]

        return result
    
    def ls(self, path="/", dirs=None):
        return [ "%s" % (dent['name']) for dent in self.longls(path,dirs) ]

    def istat(self, inode_id):
        dbh = DB.DBO()
        result = {}
        dbh.execute("select attribute, value from AFF4_attribute join AFF4 on AFF4_attribute.attribute_id = AFF4.attribute_id where urn_id = %r", inode_id)
        for row in dbh:
            attribute = row['attribute']
            try:
                result[attribute].append(row['value'])
            except KeyError:
                result[attribute] = [row['value'],]

        return result

    def isdir(self,directory):
        directory=posixpath.normpath(directory)
        if directory=='/': return 1
        
        dbh=DB.DBO(self.case)
        dirname=FlagFramework.normpath(posixpath.dirname(directory))
        dbh.execute("select type from vfs where path=%r and name=%r and "
                    "type='directory' limit 1",(dirname,
                                                posixpath.basename(directory)))
        return dbh.fetch()
        
    def resetscanfs(self,scanners):
        for i in scanners:
            try:
                i.reset()
            except DB.DBError,e:
                pyflaglog.log(pyflaglog.ERRORS,"Could not reset Scanner %s: %s" % (i,e))
        
    def scanfs(self, scanners, action=None):
        ## Prepare the scanner factory for scanning:
        for s in scanners:
            s.prepare()
        
        dbh2 = DB.DBO(self.case)
        dbh3=DB.DBO(self.case)

        dbh3.execute('select inode, concat(path,name) as filename from file where mode="r/r" and status="alloc"')
        count=0
        for row in dbh3:
            # open file
            count+=1
            if not count % 100:
                pyflaglog.log(pyflaglog.INFO,"File (%s) is inode %s (%s)" % (count,row['inode'],row['filename']))
                
            try:
                fd = self.open(inode=row['inode'])
                Scanner.scanfile(self,fd,scanners)
                fd.close()
            except Exception,e:
                pyflaglog.log(pyflaglog.ERRORS,"%r: %s" % (e,e))
                continue
        
        for c in scanners:
            c.destroy()

    def lstat(self,path):
        """ standards compliant 'stat' returns a stat_result """
        dbh=DB.DBO(self.case)
        path, inode, inode_id = self.lookup(path)

        if not inode_id:
            return None

        dbh.check_index('inode','inode')
        dbh.execute("select inode_id, inode, uid, gid, unix_timestamp(mtime) as mtime, unix_timestamp(atime) as atime, unix_timestamp(ctime) as ctime, mode, links, size from inode where inode_id=%r limit 1",(inode_id))
        result = dbh.fetch()
        if not result:
            return None

        if self.isdir(path): 
            result['mode'] = 16877
        else:
            result['mode'] = 33188

        result = os.stat_result((result['mode'],1,0,result['links'] or 0,result['uid'] or 0,result['gid'] or 0,result['size'] or 0,result['atime'] or 0,result['mtime'] or 0,result['ctime'] or 0))

        return result

    def listdir(self,path):
        """ standards compliant listdir, generates directory entries. """
        return self.ls(path)
 
## These are some of the default views that will be seen in View File
def goto_page_cb(query,result,variable):
    try:
        limit = query[variable]
    except KeyError:
        limit='0'

    try:
        if query['__submit__']:
            ## Accept hex representation for limits
            if limit.startswith('0x'):
                del query[variable]
                query[variable]=int(limit,16)

            result.refresh(0,query,pane='parent')
            return
    except KeyError:
        pass
    
    result.heading("Skip directly to an offset")
    result.para("You may specify the offset in hex by preceeding it with 0x")
    result.start_form(query)
    result.start_table()
    if limit.startswith('0x'):
        limit=int(limit,16)
    else:
        limit=int(limit)

    result.textfield('Offset in bytes (%s)' % hex(limit),variable)
    result.end_table()
    result.end_form()

## Deprecated
class StringIOFile(File):
    """ This is a File object which is implemented as a StringIO.

    Use this to work with small files which would be too slow to write
    on the disk.
    """
    def look_for_cached(self):
        try:
            if self.cached_fd:
                return
        except AttributeError: pass
        
        self.cached_fd = None
        data = self.read()

        self.cached_fd = StringIO.StringIO(data)

    def seek(self, offset, rel=0):
        self.cached_fd.seek(offset,rel)

    def force_cache(self):
        self.look_for_cached()

def translate(pat):
    """Translate a shell PATTERN to a regular expression.

    There is no way to quote meta-characters.
    This is a derivative of fnmatch with some minor modifications.
    """
    i, n = 0, len(pat)
    res = ''
    while i < n:
        c = pat[i]
        i = i+1
        if c == '*':
            res = res + '[^/]*'
        elif c == '?':
            res = res + '[^/]'
        elif c == '[':
            j = i
            if j < n and pat[j] == '!':
                j = j+1
            if j < n and pat[j] == ']':
                j = j+1
            while j < n and pat[j] != ']':
                j = j+1
            if j >= n:
                res = res + '\\['
            else:
                stuff = pat[i:j].replace('\\','\\\\')
                i = j+1
                if stuff[0] == '!':
                    stuff = '^' + stuff[1:]
                elif stuff[0] == '^':
                    stuff = '\\' + stuff
                res = '%s[%s]' % (res, stuff)
        else:
            res = res + re.escape(c)
    return res

## This tells us if the pattern has a glob in it
globbing_re = re.compile("[*+?\[\]]")

def glob_sql(pattern):
    path,name = posixpath.split(pattern)

    if globbing_re.search(path):
        path_sql = "path rlike '^%s/?$'" % translate(path)
    else:
        ## Ensure that path has a / at the end:
        #if not path.endswith("/"): path=path+'/'
        
        path_sql = "path='%s'" % path

    if globbing_re.search(name):
        name_sql = "name rlike '^%s$'" % translate(name)
    else:
        name_sql = DB.expand("name=%r", name)
    
    if name and path:
        sql = "select concat(path,name) as path from vfs where %s and %s group by vfs.path,name" % (path_sql,name_sql)
    elif name:
        sql = "select concat(path,name) as path from vfs where %s group by vfs.path,name" % name_sql
    elif path:
        #sql = "%s and name=''" % path_sql
        sql = "select path from vfs where %s group by path" % path_sql
    else:
        ## Dont return anything for an empty glob
        sql = "select * from vfs where 1=0"

    return sql
    
def glob(pattern, case=None):
    dbh = DB.DBO(case)
    dbh.execute(glob_sql(pattern))
    return [ row['path'] for row in dbh if row['path'] ]
##    for row in dbh:
##        if row['path']:
##            yield row['path']

## Unit Tests
import unittest

class VFSTests(unittest.TestCase):
    """ Test implementation of the VFS """
    test_case = "PyFlagTestCase"
    def test00preLoadCase(self):
        """ Reset case """
        import pyflag.pyflagsh as pyflagsh
        
        pyflagsh.shell_execv(command = "execute",
                             argv=["Case Management.Remove case",'remove_case=%s' % self.test_case])

        pyflagsh.shell_execv(command="execute",
                             argv=["Case Management.Create new case",'create_case=%s' % self.test_case])

    def test01VFSTests(self):
        """ Test common aspects of VFSCreate """
        ## Get a handle to our VFS:
        vfs = DBFS(self.test_case)
        dbh = DB.DBO(self.test_case)
        ## Try to create a node without parent directories:
        vfs.VFSCreate(None, "TestInode1", "/toplevel/somedir/somefile")
        vfs.VFSCreate(None, "TestInode1", "/toplevel/somedir/somefile2")

        ## Verify that the parent directories are created:
        dbh.execute("select * from file where path='/toplevel/' and name='somedir'")
        self.assert_(dbh.fetch())

        ## Create a node based on another node:
        vfs.VFSCreate("TestInode1", "TestInode2", "foobar")
        dbh.execute("select * from file where path='/toplevel/somedir/somefile/' and name='foobar' and inode='TestInode1|TestInode2'")
        self.assert_(dbh.fetch())

        ## Multiple creates:
        #vfs.VFSCreate(None, "TestInode1", "/toplevel/somedir/somefile")
        #dbh.execute("select count(*) from file where path='/toplevel/somedir/somefile/' and name='foobar' and inode='TestInode1|TestInode2'")
        #self.assert_(dbh.fetch())
        
