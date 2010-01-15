""" This module contains functions which are shared among many plugins """
# ******************************************************
# Copyright 2009: Commonwealth of Australia.
#
# Michael Cohen <scudette@users.sourceforge.net>
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
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.Registry as Registry
from pyflag.Scanner import *
import pyflag.Scanner as Scanner
import dissect
import struct,sys,cStringIO
import pyflag.DB as DB
import pyflag.FlagFramework as FlagFramework
import pyflag.Magic as Magic
import reassembler, pypcap
import pdb
from pyflag.ColumnTypes import AFF4URN, IntegerType, IPType, ShortIntegerType, TimestampType, StateType
import pyflag.Reports as Reports
import pyflag.FileSystem as FileSystem
import pyflag.Store as Store
import pyaff4
from pyflag.attributes import *

oracle = pyaff4.Resolver()

PCAP_FILE_CACHE = Store.FastStore()

class PCAPMagic(Magic.Magic):
    """ Identify PCAP files """
    type = "PCAP tcpdump file"
    mime = "binary/x-pcap"
    default_score = 100

    regex_rules = [
        ( r"\xd4\xc3\xb2\xa1", (0,1)),
        ( r"\xa1\xb2\xc3\xd4", (0,1))
        ]

    samples = [
        ( 100, "\xd4\xc3\xb2\xa1sddsadsasd")
        ]

class ConnectionDetailsTable(FlagFramework.CaseTable):
    """ Connection Details - Contains details about each connection """
    name ='connection_details'
    columns = [
        [ AFF4URN, {} ],
        [ IntegerType, dict(name='Reverse', column='reverse')],
        [ IPType, dict(name='Source IP', column='src_ip')],
        [ ShortIntegerType, dict(name='Source Port', column='src_port')],
        [ IPType, dict(name='Destination IP', column='dest_ip')],
        [ ShortIntegerType, dict(name='Destination Port', column='dest_port')],
        [ IntegerType, dict(name='ISN', column='isn'), 'unsigned default 0'],
        [ TimestampType, dict(name='Timestamp', column='ts_sec')],
        [ StateType, dict(name='Type', column='type', states={'tcp':'tcp', 'udp':'udp'})]
        ]

class ViewConnections(Reports.PreCannedCaseTableReports):
    """ View the connection table """
    description = "View the connection table"
    name = "/Network Forensics/View Connections"
    family = "Network Forensics"
    default_table = "ConnectionDetailsTable"
    columns = ['Inode', "Timestamp", "Source IP", "Source Port", "Destination IP",
               "Destination Port", "Type"]

def make_processor(case, scanners, urn_dispatcher, cookie):
    """ Creates a new processor and returns it - you will need to feed
    it packets and it will create streams on the AFF4 case file.

    urn_dispatcher is a dict with keys as ints and values as URNs of
    source files. When a new pcap file is opened it can receive a
    unique pcap_file_id. All packets from this file will carry this ID
    and we use this urn_dispatcher dict to map them back to a URN.
    """
    def Callback(mode, packet, connection):
        if mode == 'est':
            if 'map' not in connection:
                ## Lookup the urn this packet came from
                urn = urn_dispatcher[packet.pcap_file_id]
                ip = packet.find_type("IP")

                ## We can only get tcp or udp packets here
                try:
                    tcp = packet.find_type("TCP")
                except AttributeError:
                    tcp = packet.find_type("UDP")

                base_urn = "/%s-%s/%s-%s/" % (
                    ip.source_addr, ip.dest_addr,
                    tcp.source, tcp.dest)

                timestamp = pyaff4.XSDDatetime()
                timestamp.set(packet.ts_sec)
                map_stream = CacheManager.AFF4_MANAGER.create_cache_map(
                    case, base_urn + "forward", timestamp = timestamp,
                    target = urn)
                connection['map'] = map_stream

                ## These streams are used to point at the start of
                ## each packet header - this helps us get back to
                ## the packet information for each bit of data
                map_stream_pkt = CacheManager.AFF4_MANAGER.create_cache_map(
                    case, base_urn + "forward.pkt", timestamp = timestamp,
                    target = urn, inherited = map_stream.urn)
                connection['map.pkt'] = map_stream_pkt

                r_map_stream = CacheManager.AFF4_MANAGER.create_cache_map(
                    case, base_urn + "reverse", timestamp = timestamp,
                    target = urn, inherited = map_stream.urn)
                connection['reverse']['map'] = r_map_stream

                ## These streams are used to point at the start of
                ## each packet header - this helps us get back to
                ## the packet information for each bit of data
                r_map_stream_pkt = CacheManager.AFF4_MANAGER.create_cache_map(
                    case, base_urn + "reverse.pkt", timestamp = timestamp,
                    target = urn, inherited = r_map_stream.urn)
                connection['reverse']['map.pkt'] = r_map_stream_pkt


                ## Add to connection table
                map_stream.insert_to_table("connection_details",
                                           dict(reverse = r_map_stream.inode_id,
                                                src_ip = ip.src,
                                                src_port = tcp.source,
                                                dest_ip = ip.dest,
                                                dest_port = tcp.dest,
                                                _ts_sec = "from_unixtime(%s)" % packet.ts_sec,
                                                )
                                           )

        elif mode == 'data':
            try:
                tcp = packet.find_type("TCP")
            except AttributeError:
                tcp = packet.find_type("UDP")

            try:
                length = len(tcp.data)
            except: return
            
            urn = urn_dispatcher[packet.pcap_file_id]

            if packet.offset==0: pdb.set_trace()

            connection['map'].write_from(urn, packet.offset + tcp.data_offset, length)
            connection['map.pkt'].write_from(urn, packet.offset, length)

        elif mode == 'destroy':
            if connection['map'].size > 0 or connection['reverse']['map'].size > 0:

                map_stream = connection['map']

                r_map_stream = connection['reverse']['map']

                map_stream_pkt = connection['map.pkt']
                Magic.set_magic(case, map_stream_pkt.inode_id,
                                "Packet Map")

                r_map_stream_pkt = connection['reverse']['map.pkt']
                Magic.set_magic(case, r_map_stream_pkt.inode_id,
                                "Packet Map")

                r_map_stream.set_attribute(PYFLAG_REVERSE_STREAM, map_stream.urn)
                map_stream.set_attribute(PYFLAG_REVERSE_STREAM, r_map_stream.urn)

                ## Close all the streams
                r_map_stream_pkt.close()
                map_stream_pkt.close()
                r_map_stream.close()
                map_stream.close()

                ## FIXME - this needs to be done out of process using
                ## the distributed architecture!!!

                ## Open read only versions of these streams for
                ## scanning
                dbfs = FileSystem.DBFS(case)
                map_stream = dbfs.open(inode_id = map_stream.inode_id)
                r_map_stream = dbfs.open(inode_id = r_map_stream.inode_id)

                Scanner.scan_inode_distributed(case, map_stream.inode_id,
                                               scanners, cookie)
                Scanner.scan_inode_distributed(case, r_map_stream.inode_id,
                                               scanners, cookie)

    ## Create a tcp reassembler if we need it
    processor = reassembler.Reassembler(packet_callback = Callback)

    return processor

class PCAPScanner(GenScanFactory):
    """ A scanner for PCAP files. We reasemble streams and load them
    automatically. Note that this code creates map streams for
    forward, reverse and combined streams.
    """
    def scan(self, fd, scanners, type, mime, cookie, **args):
        if "PCAP" not in type: return

        urn_dispatcher = {1: fd.urn}
        processor = make_processor(fd.case, scanners, urn_dispatcher, cookie)
        ## Now process the file
        try:
            pcap_file = pypcap.PyPCAP(fd, file_id=1)
            PCAP_FILE_CACHE.add(fd.urn, pcap_file)
        except IOError:
            pyflaglog.log(pyflaglog.WARNING,
                          DB.expand("%s does not appear to be a pcap file", fd.urn))
            return
        
        while 1:
            try:
                packet = pcap_file.dissect()
                processor.process(packet)
            except StopIteration: break

        del processor

def dissect_packet(stream_fd):
    """ Return a dissected packet in stream fd. Based on the current readptr.
    """
    dbfs = FileSystem.DBFS(stream_fd.case)
    urn = pyaff4.RDFURN()
    urn.set(stream_fd.urn.value + ".pkt")

    fd = dbfs.open(urn = urn)
    if not fd or \
            not oracle.resolve_value(stream_fd.urn, pyaff4.AFF4_TARGET, urn):
        raise RuntimeError("%s is not a stream" % stream_fd.urn)

    ## Get the file from cache
    try:
        pcap_file = PCAP_FILE_CACHE.get(urn.value)
    except KeyError:
        pcap_fd = dbfs.open(urn = urn)
        pcap_file = pypcap.PyPCAP(pcap_fd)
        PCAP_FILE_CACHE.add(urn.value, pcap_file)

    offset = stream_fd.tell()

    ## What is the current range?
    (target_offset_at_point,
     available_to_read) =  fd.get_range(offset, None)

    if available_to_read:
        ## Go to the packet
        pcap_file.seek(target_offset_at_point)

        ## Dissect it
        try:
            return pcap_file.dissect()
        except: pass

def generate_streams_in_time_order(forward_fd, reverse_fd):
    """ This generator will return the next fd who's readptr is the
    earliest in time. This is useful for parsing forward/reverse
    streams in order.

    Callers are expected to consume data off the returned fd which
    might allow the other fd to be returned next time.
    """
    ## This is how this works:
    ## 1. we have two streams

    ## 2. We dissect the packet the stream is on right now in
    ## both streams to find the one that is earlier in time.

    ## 3. We then yield this stream - hopefully the caller will
    ## consume some data from this stream allowing us to make
    ## progress.

    ## Note that for efficiency we also attach the dissected packet to
    ## the stream.
    while 1:
        forward_packet = dissect_packet(forward_fd)
        reverse_packet = dissect_packet(reverse_fd)

        ## Go for the earlier stream in time
        try:
            if forward_packet.ts_sec < reverse_packet.ts_sec:
                fd = forward_fd
                fd.current_packet = forward_packet
            else:
                fd = reverse_fd
                fd.current_packet = reverse_packet

        except AttributeError:
            ## If one stream has no valid packet, we forget it
            ## and concentrate on the other stream until its
            ## done. If both streams are done we break
            if not forward_packet:
                if not reverse_packet: break
                fd = reverse_fd
                fd.current_packet = reverse_packet

            elif not reverse_packet:
                fd = forward_fd
                fd.current_packet = forward_packet

        yield fd

class ViewDissectedPacket(Reports.report):
    """ View Dissected packet in a tree. """
    parameters = {'id':'numeric'}
    name = "View Packet"
    family = "Network Forensics"
    description = "Views the packet in a tree"

    def form(self,query,result):
        try:
            result.case_selector()
            result.textfield('Packet ID','id')
        except KeyError:
            pass

    def display(self,query,result):
        dbh = DB.DBO(query['case'])
        dbh.execute("select * from pcap where id=%r limit 1", query['id'])
        row=dbh.fetch()
        
        io = IO.open(query['case'], row['iosource'])
        packet = pypcap.PyPCAP(io)
        packet.seek(row['offset'])
        dissected_packet = packet.dissect()
        
        id = int(query['id'])
        
        def get_node(branch):
            """ Locate the node specified by the branch.

            branch is a list of attribute names.
            """
            result = dissected_packet
            for b in branch:
                try:
                    result = getattr(result, b)
                except: pass

            return result
        
        def tree_cb(path):
            branch = FlagFramework.splitpath(path)
            
            node = get_node(branch)
            try:
                for field in node.list():
                    if field.startswith("_"): continue

                    child = getattr(node, field)
                    try:
                        yield  ( field, child.get_name(), 'branch')
                    except AttributeError:
                        yield  ( field, field, 'leaf')

            except AttributeError:
                pass
            
            return
        
        def pane_cb(path,result):
            branch = FlagFramework.splitpath(path)
            
            node = get_node(branch)

            result.heading("Packet %s" % id)
            data = dissected_packet.serialise()
            
            h=FlagFramework.HexDump(data, result)
            try:
                result.text("%s" % node.get_name(), font='bold')
                result.text('',style='black', font='normal')
                start,length = node.get_range()
                
            except AttributeError:
                result.text("%s\n" % node, style='red', wrap='full', font='typewriter', sanitise='full')
                result.text('',style='black', font='normal')
                node = get_node(branch[:-1])
                start,length = node.get_range(branch[-1])

            h.dump(highlight=[[start,length,'highlight'],])

            return

        result.tree(tree_cb=tree_cb, pane_cb=pane_cb, branch=[''])

        ## We add forward and back toolbar buttons to let people move
        ## to next or previous packet:
        dbh.execute("select min(id) as id from pcap")
        row = dbh.fetch()

        new_query=query.clone()
        if id>row['id']:
            del new_query['id']
            new_query['id']=id-1
            result.toolbar(text="Previous Packet",icon="stock_left.png",link=new_query)
        else:
            result.toolbar(text="Previous Packet",icon="stock_left_gray.png")
            
        dbh.execute("select max(id) as id from pcap")
        row = dbh.fetch()
        
        if id<row['id']:
            del new_query['id']
            new_query['id']=id+1
            result.toolbar(text="Next Packet",icon="stock_right.png",link=new_query)
        else:
            result.toolbar(text="Next Packet",icon="stock_right_gray.png")

