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

""" PyFlag module for Timeline analysis.
"""
from pyflag.ColumnTypes import IntegerType,TimestampType,FilenameType, StringType, StateType, AFF4URN
### FIXME - this module needs updating!!!!

import pyflag.Reports as Reports
from pyflag.FlagFramework import Curry,query_type
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()

class MACTimes(FlagFramework.EventHandler):
    def create(self, dbh, case):
        dbh.execute("""create table if not exists mac(
        `inode_id` INT NOT NULL default 0,
        `status` varchar(8) default '',
        `time` timestamp NOT NULL default '0000-00-00 00:00:00',
        `m` int default NULL,
        `a` tinyint default NULL,
        `c` tinyint default NULL,
        `d` tinyint default NULL,
        `name` text
        ) """)

class Timeline(Reports.report):
    """ View file MAC times in a searchable table """
    name = "View File Timeline"
    family = "Disk Forensics"
    description = "Browse file creation, modification, and access times"

    def form(self, query, result):
        result.case_selector()

    def analyse(self, query):
        dbh = self.DBO(query['case'])
        temp_table = dbh.get_temp()
        dbh.check_index("inode","inode")
        dbh.execute("create temporary table %s select i.inode_id,f.status,mtime as `time`,1 as `m`,0 as `a`,0 as `c`,0 as `d`,concat(path,name) as `name` from inode as i left join file as f on i.inode=f.inode" %
                    (temp_table, ));
        dbh.execute("insert into %s select i.inode_id,f.status,atime,0,1,0,0,concat(path,name) from inode as i left join file as f on i.inode_id=f.inode_id" % (temp_table,))
        dbh.execute("insert into %s select i.inode_id,f.status,ctime,0,0,1,0,concat(path,name) from inode as i left join file as f on i.inode_id=f.inode_id" % (temp_table, ))
        dbh.execute("insert into %s select i.inode_id,f.status,dtime,0,0,0,1,concat(path,name) from inode as i left join file as f on i.inode_id=f.inode_id" % (temp_table, ))
        dbh.execute("insert into mac select inode_id,status,time,sum(m) as `m`,sum(a) as `a`,sum(c) as `c`,sum(d) as `d`,name from %s where time>0 group by time,name order by time,name" % temp_table)
        dbh.check_index("mac","inode_id")
        
    def progress(self, query, result):
        result.heading("Building Timeline")
    
    def display(self, query, result):
        dbh = self.DBO(query['case'])
        result.heading("File Timeline for Filesystem")
        result.table(
            elements=[ TimestampType('Timestamp','time'),
                       AFF4URN(case=query['case']),
                       DeletedType(),
                       BinaryType('m',"m"),
                       BinaryType('a',"a"),
                       BinaryType('c',"c"),
                       BinaryType('d',"d"),
                       FilenameType(),
                       ],
            table='mac',
            case=query['case'],
            )

    def reset(self, query):
        dbh = self.DBO(query['case'])
        dbh.execute("drop table mac")
