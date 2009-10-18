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
#  Version: FLAG  $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
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
""" This module implements a scanning mechanism for operating on all files within a given filesyst

Scanners are pieces of code that are run on all the files in a filesystem when the filesystem is loaded. The purpose of scanners is to extract meta data about files in the filesystem and make deductions.

The GenScan abstract class documents a Generic scanner. This scanner is applied on every file in a filesystem during a run of the FileSystem's scan method.

Scanners are actually factory classes and must be inherited from GenScanFactory. 
"""
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.pyflaglog as pyflaglog
import os,imp, StringIO
import re,pdb, time
import pyflag.Registry as Registry
import pyflag.DB as DB
import pyflag.FlagFramework as FlagFramework
import fnmatch
import ScannerUtils
import pyflag.CacheManager as CacheManager
import pyflag.Magic as Magic
import pyflag.Farm as Farm

class GenScanFactory:
    """ Abstract Base class for scanner Factories.
    
    The Scanner Factory is a specialised class for producing scanner
    objects. It will be instantiated once at the begining of the run,
    and destroyed at the end of the run. It will be expected to
    produce a new Scanner object for each file in the filesystem.
    """
    ## Should this scanner be on by default?
    default=False
    
    ## The default group - this will cause all scanners to go to this
    ## scanner group by default.
    group = 'GeneralForensics'

    ## This is a list of scanner names which we depend on. Depending
    ## on a scanner will force it to be enabled whenever we are
    ## enabled.
    depends = []

    ## This is the name of the group which this scanner will render
    ## under in the GUI:
    group = ''
            
    ## Relative order of scanners - Higher numbers come later in the order
    order=10

    def scan(self, fd, scanners, type, mime, cookie):
        """ This is the new scan method - scanners just implement this
        method and go from there.

        Cookie is a magic value which must be passed to any
        distributed scan requests we make. This is used to ensure that
        scanners which launch other jobs are not terminated before
        their own jobs are done.
        """
        
def scan_inode_distributed(case, inode_id, scanners, cookie):
    """ Schedules a job to scan the inode by an available worker.

    Note this will actually happen out of process.
    """
    Farm.post_job('Scan', dict(case=case, inode_id=inode_id, scanners=scanners), cookie)
    return

    #return scan_inode(case, inode_id, factories, cookie)
    pdbh = DB.DBO()

    ## We require that all scanning calls have a valid cookie. The
    ## following helps to trap bugs by scanners not passing the cookie
    ## along.
    if cookie == 0:
        raise RuntimeError( "Invalid cookie")
    ## This is a cookie used to identify our requests so that we
    ## can check they have been done later.
    pdbh.insert("jobs",
                command = 'Scan',
                arg1 = case,
                arg2 = inode_id,
                arg3 = ','.join([f.name for f in factories]),
                cookie=cookie,
                _fast = True
                )
    
    ## This is running in the worker itself - we can not wake up the
    ## other workers from here.
    Farm.wake_workers()
    
MESSAGE_COUNT = 0
### This is used to scan a file with all the requested scanner factories
def scan_inode(case, inode_id, scanners, cookie, force=False):
    """ Scans the given inode_id with all the factories provided. Each
    factory is used to instantiate a Scan() object, then we call
    Scan.scan() on the inode_id.

    if force is set we just scan anyway - even if its already been scanned.
    """
    import pyflag.FileSystem as FileSystem
    fsfd = FileSystem.DBFS(case)
    fd = fsfd.open(inode_id=inode_id)
    stat = fd.stat()
    
    # instantiate a scanner object from each of the factory. We only
    # instantiate scanners from factories which have not been run on
    # this inode previously. We find which factories were already run
    # by checking the inode table.  Note that we still pass the full
    # list of factories to the Scan class so that it may invoke all of
    # the scanners on new files it discovers.
    dbh = DB.DBO(case)    
    dbh.execute("select inode_id, scanner_cache from vfs where inode_id=%r limit 1",
                fd.inode_id)
    row=dbh.fetch()
    try:
        scanners_run =row['scanner_cache'].split(',')
    except:
        scanners_run = []

    ## Force the scanners to run anyway
    if force: scanners_run = []
    
    fd.inode_id = row['inode_id']

    ## The new scanning framework is much simpler - we just call the
    ## scan() method on each factory.
    m = Magic.MagicResolver()
    type, mime = m.find_inode_magic(case, fd.inode_id)

    for c in get_factories(scanners):
        if c.__class__.__name__ not in scanners_run:
            fd.seek(0)
            try:
                c.scan(fd, scanners=scanners, type=type, mime=mime, cookie=cookie)
            except Exception,e:
                print e
                pdb.post_mortem()
    
    global MESSAGE_COUNT
    MESSAGE_COUNT += 1
    if not MESSAGE_COUNT % 50:
        messages = DB.expand("Scanning file %s/%s (inode %s)",
                             (stat['path'],stat['name'],stat['inode_id']))
        pyflaglog.log(pyflaglog.DEBUG, messages)
    else:
        messages = DB.expand("Scanning file %s/%s (inode %s)",
                             (stat['path'],stat['name'],stat['inode_id']))
        pyflaglog.log(pyflaglog.VERBOSE_DEBUG, messages)

    # Store the fact that we finished in the inode table:
    scanner_names = ','.join([ c.__class__.__name__ for c in factories ])
    try:
        dbh.execute("update vfs set scanner_cache = concat_ws(',',scanner_cache, %r) where inode_id=%r", (scanner_names, fd.inode_id))
    except DB.DBError:
        pass

class Drawer:
    """ This class is responsible for rendering scanners of similar classes.

    This class should be declared as an inner class of the scanner.
    """
    description = "Description of main scanner"
    group = "Name of group"
    child_scanners = None
    default = True

    def __init__(self):
        ## Populate the classes of scanners which depend on us:
        self.child_scanners = []
        for c in Registry.SCANNERS.classes:
            if c.group == self.group:
                ## Its our scanner
                self.child_scanners.append(c)

    def get_group_name(self):
        return "scangroup_%s" % self.group

    def get_parameters(self):
        for i in self.child_scanners:
            try:
                yield "scan_%s" % i.__name__,'onoff'
            except:
                continue

    def add_defaults(self,dest_query,src_query):
        """ Given a src_query object with some scan_ entries, we add
        scan_ entries initialised to their default values until
        the full contained set is represented.
        """
        try:
            scan_group_name = self.get_group_name()

            if src_query[scan_group_name]=='on':
                for i in self.child_scanners:
                    scan_name = 'scan_%s' % i.__name__
                    del dest_query[scan_name]

                    ## If i is not specified, we use the default for
                    ## this scanner:
                    if not src_query.has_key('scan_%s' % i.__name__):
                        if cls.default:
                            dest_query[scan_name]='on'
                        else:
                            dest_query[scan_name]='off'
                    else:
                        dest_query[scan_name]=src_query[scan_name]
        except KeyError:
            pass

    def form(self,query,result):
        left = result.__class__(result)
        scan_group_name = self.get_group_name()

        ## If there is no scan_group defined, we use the default value
        if not query.has_key(scan_group_name):
            if self.default:
                query[scan_group_name]='on'
                result.defaults[scan_group_name]='on'
            else:
                query[scan_group_name]='off'
                result.defaults[scan_group_name]='off'

        ## Add defaults for the scanners contained:
        for cls in self.child_scanners:
            if not query.has_key('scan_%s' % cls.__name__):
                if cls.default:
                    result.hidden('scan_%s' % cls.__name__,'on')
                else:
                    result.hidden('scan_%s' % cls.__name__,'off')
            
        def configure_cb(query,result):
            try:
                if query['refresh']:
                    del query['refresh']

                    result.refresh(0,query,pane="parent")
            except KeyError:
                pass

            ## Draw the gui for all the classes we manage:
            result.decoration = 'naked'
            result.start_form(query,pane="parent")
            result.start_table()

            self.add_defaults(query,query.clone())

            for cls in self.child_scanners:
                scanner_desc = cls.__doc__.splitlines()[0]
                
                ## Add an enable/disable selector
                result.const_selector(scanner_desc,"scan_%s" % cls.__name__,[
                    'on','off'],['Enabled','Disabled'] )
                
            result.end_table()
            result.end_form()

        right=result.__class__(result)
        right.popup(configure_cb,"Configure %s" % self.group,icon="spanner.png")
        left.row(right,self.description)
        result.const_selector(left,
                           scan_group_name,
                           ['on','off'],['Enabled','Disabled'])

## This is a global store for factories:
import pyflag.Store as Store

factories = Store.Store(50)

def get_factories(scanners):
    """ Scanner factories are obtained from the Store or created as
    required.
    """
    ## Ensure dependencies are satisfied
    scanners = ScannerUtils.fill_in_dependancies(scanners)
    
    ## First prepare the required factories:
    result = []
    for scanner in scanners:
        try:
            f=factories.get(scanner)
        except KeyError:
            try:
                cls=Registry.SCANNERS.dispatch(scanner)
            except:
                #pyflaglog.log(pyflaglog.WARNING, "Unable to find scanner for %s", scanner)
                continue

            #Instatiate it:
            f=cls()

            ## Store it:
            factories.put(f,key=scanner)

        result.append(f)

    return result
