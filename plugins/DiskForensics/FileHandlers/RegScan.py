""" This Module handles windows registry files.

This module contains a scanner to trigger off on registry files and scan them seperately. A report is also included to allow tree viewing and table searching of registry files.
"""
import os.path
import pyflag.logging as logging
from pyflag.Scanner import *
import plugins.DiskForensics as DiskForensics

class RegistryScan(GenScanFactory):
    """ Load in Windows Registry files """
    def __init__(self,dbh, table):
        self.dbh=dbh
        self.table=table
        self.dbh.execute('create table if not exists reg_%s (`path` CHAR(250), `size` SMALLINT, `type` CHAR(12),`reg_key` VARCHAR(200),`value` text)',self.table)

    def reset(self):
        self.dbh.execute('drop table if exists reg_%s',self.table)
        self.dbh.execute('drop table if exists regi_%s',self.table)
        
    def destroy(self):
        ## Create the directory indexes to speed up tree navigation:
        self.dbh.execute("create table if not exists regi_%s (`dirname` TEXT NOT NULL ,`basename` TEXT NOT NULL,KEY `dirname` (`dirname`(100)))",self.table)
        dirtable = {}
        self.dbh.execute("select path from reg_%s",self.table)
        for row in self.dbh:
            array=row['path'].split("/")
            while len(array)>1:
                new_dirname="/".join(array[:-1])
                new_basename=array.pop()
                try:
                    ## See if the value is already in the dictionary
                    dirtable[new_dirname].index(new_basename)
                except ValueError:
                    dirtable[new_dirname].append(new_basename)
                except KeyError:
                    dirtable[new_dirname]=[new_basename]

        for k,v in dirtable.items():
            for name in v:
                self.dbh.execute("insert into regi_%s set dirname=%r,basename=%r",(self.table,k,name))

        ## Add indexes:
        self.dbh.execute("alter table reg_%s add index(path)",self.table)

    class Scan(StoreAndScan):
        def boring(self,metadata):
            return metadata['mime'] not in (
                'application/x-winnt-registry',
                'application/x-win9x-registry',
                )

        def external_process(self,filename):
            self.dbh.MySQLHarness("regtool -f %s -t reg_%s -p %r " % (filename,self.ddfs.table,self.ddfs.lookup(inode=self.inode)))

## Report to browse Loaded Registry Files:
class BrowseRegistry(DiskForensics.BrowseFS):
    """ Browse a Windows Registry file """
    description="Browse a windows registry hive file (found in c:\winnt\system32\config\) "
    name = "Browse Registry Hive"

    def display(self,query,result):
        result.heading("Registry Hive in image %r" % query['fsimage'])
        dbh = self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['fsimage'])
        new_q=query.clone()
            
        #Make a tree call back:
        def treecb(branch):
            """ This call back will render the branch within the registry file. """
            path ='/'.join(branch)
            dbh = self.DBO(query['case'])

            ##Show the directory entries:
            dbh.execute("select basename from regi_%s where dirname=%r and length(basename)>1 group by basename",(tablename,path))
            for row in dbh:
                tmp=self.ui()
                tmp.link(row['basename'],new_q,mode='table',where_Path="%s/%s" %(path,row['basename']))
                yield(([row['basename'],tmp,'branch']))
                
        ## End Tree Callback

        try:
            try:
                if query['mode']=='table':
                    del new_q['mode']
                    for i in new_q.keys():
                        if i.startswith('where_'):
                            del new_q[i]

                    left=self.ui(result)
                    left.link("View Tree",new_q)
                    result.row(left)
                    result.table(
                        columns=['path','type','reg_key','size','value'],
                        names=['Path','Type','Key','Size','Value'],
                        links=[ result.make_link(new_q,'open_tree',mark='target') ],
                        table='reg_%s'%tablename,
                        case=query['case'],
                        )

                elif query['mode']=='display':
                    del new_q['mode']
                    key = query['key']
                    path=query['path']
                    del new_q['key']
                    del new_q['path']
                    left=self.ui(result)
                    left.link("View Tree",new_q)
                    result.row(left)
                    result.end_table()
                    result.para("Key %s/%s:" % (path,key))

                    def hexdump(query):
                        """ Show the hexdump for the key """
                        out = self.ui()
                        dbh.execute("select value from reg_%s where path=%r and reg_key=%r",(tablename,path,key))
                        row=dbh.fetch()
                        if row:
                            FlagFramework.HexDump(row['value'],out).dump()
                        return out

                    def strings(query):
                        """ Draw the strings in the key """
                        out = self.ui()
                        out.para("not implimented yet")
                        return out

                    def stats(query):
                        """ display stats on a key """
                        out = self.ui()
                        out.para("not implimented yet")
                        return out

                    result.notebook(
                        names=["HexDump","Strings","Statistics"],
                        callbacks=[hexdump,strings,stats],
                        context="display_mode"
                        )

            except KeyError,e:
                ## Display tree output
                del new_q['mode']
                del new_q['open_tree']

                def pane_cb(branch,table):
                    try:
                        path=query['open_tree']
                    except KeyError:
                        path = '/'.join(branch);

                    # now display keys in table
                    new_q['mode'] = 'display'
                    new_q['path']=path
                    table.table(
                        columns=['reg_key','type','size',"if(length(value)<50,value,concat(left(value,50),' .... '))"],
                        names=('Key','Type','Size','Value'),
                        table='reg_%s' % tablename,
                        where="path=%r" % path,
                        case=query['case'],
                        links=[ result.make_link(new_q, 'key') ]
                        )

                left=self.ui(result)
                left.link("View Table",new_q,mode='table')
                result.row(left)

                # display paths in tree
                result.tree(tree_cb=treecb,pane_cb=pane_cb,branch=[''])

        except DB.DBError,e:
            result.heading("Error occured")
            result.text('It appears that no registry tables are available. Maybe no registry files were found during scanning.')
            result.para('The Error returned by the database is %s' % e)
            
    def reset(self,query):
        dbh = self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['fsimage'])
        
        dbh.execute('drop table if exists reg_%s',tablename)
        dbh.execute('drop table if exists regi_%s',tablename)