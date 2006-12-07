""" This module implements a simple stream reassembler.
"""
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.Registry as Registry
from pyflag.Scanner import *
import struct,sys,StringIO
import pyflag.DB as DB
import pyflag.FileSystem as FileSystem
from pyflag.FileSystem import File
import pyflag.IO as IO
from pyflag.FlagFramework import query_type, get_temp_path
from NetworkScanner import *
import struct,re,os
import reassembler
from pyflag.TableObj import ColumnType, TimestampType, InodeType, IPType
import pyflag.Reports as Reports

class StreamFile(File):
    """ A File like object to reassemble the stream from individual packets.
    
    Note that this is currently a very Naive reassembler. Stream Reassembling is generally considered a very difficult task. The approach we take is to make a very simple reassembly, and have a different scanner check the stream for potetial inconsistancies.

    The inode format is:
    Scon_id/con_id/con_id

    con_ids are the connection IDs. If more than one con_id is
    specified we merge all connections into the same stream based on
    arrival time.
    """
    specifier = 'S'

    def __init__(self, case, fd, inode):
        File.__init__(self,case, fd, inode)

        self.stat_cbs.extend([ self.show_packets, self.combine_streams ])
        self.stat_names.extend([ "Show Packets", "Combined streams"])

        ## This is a cache of packet lists that we keep so we do not
        ## have to hit the db all the time.
        self.packet_list = None

        dbh = DB.DBO(self.case)
        
        ## Ensure we have an index on this column
        dbh.check_index("connection","con_id")
        dbh.check_index("connection_details","inode")

        ## Fill in some vital stats
        dbh.execute("select con_id, reverse, src_ip, dest_ip, src_port, dest_port, ts_sec from `connection_details` where inode=%r limit 1", inode)
        row=dbh.fetch()
        if row:
            self.con_id = row['con_id']
            self.src_port = row['src_port']
            self.dest_port = row['dest_port']
            self.reverse = row['reverse']
            self.ts_sec = row['ts_sec']
            self.dest_ip = row['dest_ip']
            self.src_ip = row['src_ip']

        ## Are we already cached?
        if self.cached_fd:
            return

        inode = inode.split("|")[-1]

        ## We allow the user to ask for a number of streams which will
        ## be combined at the same time. This allows us to create a
        ## VFS node for both forward and reverse streams, or even
        ## totally unrelated streams which happen at the same time.

        ## This is handled by creating a "virtual stream" - a new
        ## stream with a new stream id which collects all the packets
        ## in the component streams in chronological order.

        ## We use the inode column in the connection_details table to
        ## cache this so we only have to combine the streams once.
        stream_ids = [ int(x) for x in inode[1:].split("/")]
        self.create_new_stream(stream_ids)

    def create_new_stream(self,stream_ids):
        """ Creates a new stream by combining the streams given by the list stream_ids.
        
        @return the new stream id.
        """
        if len(stream_ids)<2: return
        
        ## Store the new stream in the cache:
        dbh = DB.DBO(self.case)

        ## FIXME: This is a race we should probably lock the tables.
        dbh.execute("select min(con_id) as min from `connection_details`")
        row=dbh.fetch()
        if row['min']:
            self.con_id = row['min']-1
        else:
            self.con_id = -1

        ## This is a placeholder to reserve our con_id
        dbh.execute("insert into `connection_details` set inode=%r,con_id=%r",
                         (self.inode,self.con_id))

        dbh2 = dbh.clone()

        ## These are the fds for individual streams
        fds = []
        for s in stream_ids:
            try:
                filename = FlagFramework.get_temp_path(dbh.case,
                                         "%s|S%s" % (self.fd.inode, s))
                fds.append(open(filename))
            except IOError,e:
                fds.append(-1)

        # These are the deltas to be applied to the sequence numbers of each
        # stream to bring it into an offset in the output file.
        deltas = [0,] * len(stream_ids)

        # Flags to indicate when the streams ISN is encountered
        initials = [ True,] * len(stream_ids)

        # The output file
        out_fd = open(get_temp_path(dbh.case, self.inode),"w")
        
        dbh.execute("select con_id,seq,packet_id, length, cache_offset from `connection` where %s order by packet_id",(
            " or ".join(["con_id=%r" % a for a in stream_ids])
            ))

        dbh2.mass_insert_start("connection")

        # This is the length of the output file
        outfd_len = 0
        outfd_position = 0
        for row in dbh:
            # This is the index for this specific stream in all the above arrays
            index = stream_ids.index(row['con_id'])

            # First time we saw this stream - the seq is the ISN
            if initials[index]:
                deltas[index] -= row['seq']
                initials[index] = False

            # We need to find if we grew the output file at all:
            initial_len = outfd_len
            if row['seq']+deltas[index]>0:
                outfd_position = row['seq']+deltas[index]
            
            # We only allow 64k to be written ahead - this is commonly
            # the window length and it stops weird sequence numbers
            # from growing the file too much
            if outfd_position - initial_len > 65000:
                outfd_position = initial_len

            try:
                out_fd.seek(outfd_position)
            except Exception,e:
                print FlagFramework.get_bt_string(e)
                print outfd_position
                raise

            # Only try to write if there is a reverse file.
            if fds[index]>0:
                fds[index].seek(row['cache_offset'])
                out_fd.write(fds[index].read(row['length']))

            # Maintain the length of the file
            outfd_len = max(outfd_len, outfd_position+row['length'])

            # Basically each time we write a packet to the output fd we might
            # grow it. If we do grow it, we need to push the other streams
            # deltas to ensure that subsequent data will be written after the
            # newly written data. This is an approximation - but is adequate
            # when packets are out of order in an interactive protocol.
            for x in range(len(stream_ids)):
                if x != index:
                    deltas[x] += outfd_len-initial_len

            dbh2.mass_insert(
                con_id=self.con_id,
                packet_id=row['packet_id'],
                seq=outfd_position,
                length=row['length'],
                cache_offset=outfd_position,
                
                # This is the original id this
                # packet came from
                original_id = row['con_id'])

        dbh2.mass_insert_commit()

        out_fd.close()
        
        self.cached_fd = open(get_temp_path(dbh.case, self.inode),"r")

        ## Now create the stream in the VFS:
        fsfd = FileSystem.DBFS(self.case)
        inode = self.inode[:self.inode.rfind("|")] +"|S%s" % stream_ids[0]
        pathname = os.path.dirname(fsfd.lookup(inode = inode))+"/combined"
        fsfd.VFSCreate(None, self.inode, pathname)

    def get_packet_id(self, position=None):
        """ Gets the current packet id (where the readptr is currently at) """
        if not position:
            position = self.tell()

        if self.packet_list==None:
            dbh = DB.DBO(self.case)
            dbh.execute("""select packet_id,cache_offset from `connection` where con_id = %r order by cache_offset desc, length desc """,
                    (self.con_id))
            self.packet_list = [ (row['packet_id'],row['cache_offset']) for row in dbh ]

        ## Now try to find the packet_id in memory:
        for packet_id,cache_offset in self.packet_list:
            if cache_offset < position:
                return packet_id

        return 0
    
    def get_combined_fd(self):
        """ Returns an fd opened to the combined stream """
        ## If we are already a combined stream, we just return ourselves
        inode = self.inode.split("|")[-1]

        if '/' in inode:
            self.forward_id = int(inode[1:].split("/")[0])
            return self

        self.forward_id = self.con_id
        fsfd = FileSystem.DBFS(self.case)
        return fsfd.open(inode="%s/%s" % (self.inode,self.reverse))

    def combine_streams(self, query,result):
        """ Show both ends of the stream combined.

        In each screenfull we show a maximum of MAXSIZE characters per connection. We stop as soon as either direction reaches this many characters.
        """
        combined_fd = self.get_combined_fd()

        try:
            limit = int(query['stream_limit'])
        except:
            limit = 0

        number_of_rows = 0
        dbh = DB.DBO(self.case)
        dbh.execute("select * from `connection` where con_id = %r order by cache_offset limit %s, %s", (combined_fd.con_id, limit, config.PAGESIZE))

        for row in dbh:
            number_of_rows += 1
            combined_fd.seek(row['cache_offset'])
            ## Get the data:
            data=combined_fd.read(row['length'])
            if row['original_id']==self.forward_id:
                result.text(data,color="blue",font='typewriter',sanitise='full',wrap='full')
            else:
                result.text(data,color="red",font='typewriter',sanitise='full',wrap='full')    

        ## Make the paging buttons
        if limit > 0:
            del query['stream_limit']
            temp = limit-config.PAGESIZE
            if temp < 0:
                temp = 0

            query['stream_limit'] = temp
            result.toolbar(text="Previous page", icon="stock_left.png",
                           link = query )
        else:
            result.toolbar(text="Previous page", icon="stock_left_gray.png")

        if number_of_rows >= config.PAGESIZE:
            del query['stream_limit']
            query['stream_limit'] = limit+config.PAGESIZE
            result.toolbar(text="Next page", icon="stock_right.png",
                           link = query )
        else:
            result.toolbar(text="Next page", icon="stock_right_gray.png")

    def show_packets(self,query,result):
        """ Shows the packets which belong in this stream """
        combined_fd = self.get_combined_fd()

        def show_data(value):
            offset, length = value.split(",")
            ui=result.__class__(result)
            ## We read at most this many chars from the packet:
            combined_fd.seek(int(offset))
            data=combined_fd.read(min(int(length),50))

            if(len(data) ==50):
                data += "  ...."

            ui.text(data, sanitise='full', font='typewriter')
            return ui

        result.table(
            elements = [ ColumnType('Packet ID','packet_id',
                                    link = query_type(family="Network Forensics",
                                                      report='View Packet',
                                                      case=query['case'],
                                                      open_tree ="/eth/payload/payload/data",
                                                      __target__='id')),
                         TimestampType('Date','pcap.ts_sec'),
                         ColumnType('Length','con.length'),
                         ColumnType('Data','concat(con.cache_offset, ",", con.length)',
                                    callback = show_data) ],
            
            table= '`connection` as con , pcap',
            where = 'con_id="%s" and packet_id=id ' % combined_fd.con_id,
            case=query['case']
            )


class OffsetFile(File):
    """ A simple offset:length file driver.

    The inode name specifies an offset and a length into our parent Inode.
    The format is offset:length
    """
    specifier = 'o'
    def __init__(self, case, fd, inode):
        File.__init__(self, case, fd, inode)

        ## We parse out the offset and length from the inode string
        tmp = inode.split('|')[-1]
        tmp = tmp[1:].split(":")
        self.offset = int(tmp[0])
        self.readptr=0
        
        ## Seek our parent file to its initial position
        self.fd.seek(self.offset)

        try:
            self.size=int(tmp[1])
        except IndexError:
            self.size=sys.maxint

    def seek(self,offset,whence=0):
        if whence==2:
            self.readptr=self.size+offset
        elif whence==1:
            self.readptr+=offset
        else:
            self.readptr=offset

        self.fd.seek(self.offset + self.readptr)

    def tell(self):
        return self.readptr
    
    def read(self,length=None):
        available = self.size - self.readptr
        if length==None:
            length=available
        else:
            if length > available:
                length = available

        if(length<0): return ''

        result=self.fd.read(length)
        
        self.readptr+=len(result)
        return result

import StringIO

## This is a memory cached version of the offset file driver - very useful for packets:
class MemroyCachedOffset(StringIO.StringIO,File):
    specifier = 'O'
    def __init__(self, case, fd, inode):
        File.__init__(self, case, fd, inode)

        ## We parse out the offset and length from the inode string
        tmp = inode.split('|')[-1]
        tmp = tmp[1:].split(":")
        fd.seek(int(tmp[0]))

        try:
            self.size=int(tmp[1])
        except IndexError:
            self.size=sys.maxint
            
        StringIO.StringIO.__init__(self, fd.read(self.size))

class ViewConnections(Reports.report):
    """ View the connection table """
    description = "View the connection table"
    name = "View Connections"
    family = "Network Forensics"

    def display(self, query,result):
        result.table(
            elements = [ InodeType('Inode','inode', case=query['case']),
                         TimestampType('TimeStamp','ts_sec'),
                         IPType('Source','src_ip'),
                         ColumnType('Src Port','src_port'),
                         IPType('Destination','dest_ip'),
                         ColumnType('Dest Port','dest_port')],
            table = 'connection_details',
            case = query['case'],
            )
