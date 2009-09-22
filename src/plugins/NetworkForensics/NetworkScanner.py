""" This module contains functions which are shared among many plugins """
# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
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
import pyflag.aff4.aff4 as aff4
import pyflag.Magic as Magic
import reassembler, pypcap
import pdb
from aff4.aff4_attributes import *
from pyflag.ColumnTypes import AFF4URN, IntegerType, IPType, ShortIntegerType, TimestampType, StateType
import pyflag.Reports as Reports

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


class PCAPScanner(GenScanFactory):
    """ A scanner for PCAP files. We reasemble streams and load them
    automatically. Note that this code creates map streams for
    forward, reverse and combined streams.
    """
    def scan(self, fd, factories, type, mime):
        if "PCAP" not in type: return
        
        def Callback(mode, packet, connection):
            if mode == 'est':
                if 'map' not in connection:
                    ip = packet.find_type("IP")

                    ## We can only get tcp or udp packets here
                    try:
                        tcp = packet.find_type("TCP")
                    except AttributeError:
                        tcp = packet.find_type("UDP")

                    base_urn = "/%s-%s/%s-%s/" % (
                        ip.source_addr, ip.dest_addr,
                        tcp.source, tcp.dest)

                    map_stream = CacheManager.AFF4_MANAGER.create_cache_map(
                        fd.case, base_urn + "forward", timestamp = packet.ts_sec,
                        target = fd.urn)
                    connection['map'] = map_stream

                    combined_stream = CacheManager.AFF4_MANAGER.create_cache_map(
                        fd.case, base_urn + "combined", timestamp = packet.ts_sec,
                        target = fd.urn, inherited = map_stream.urn)
                    
                    connection['reverse']['combined'] = combined_stream
                    connection['combined'] = combined_stream
                    
                    r_map_stream = CacheManager.AFF4_MANAGER.create_cache_map(
                        fd.case, base_urn + "reverse", timestamp = packet.ts_sec,
                        target = fd.urn, inherited = map_stream.urn)
                    connection['reverse']['map'] = r_map_stream

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

                length = len(tcp.data)
                connection['map'].write_from("@", packet.offset + tcp.data_offset, length)
                connection['combined'].write_from("@", packet.offset + tcp.data_offset,
                                                  length)

            elif mode == 'destroy':
                if connection['map'].size > 0 or connection['reverse']['map'].size > 0:
                    map_stream = connection['map']
                    map_stream.close()

                    r_map_stream = connection['reverse']['map']
                    r_map_stream.close()

                    combined_stream = connection['combined']
                    combined_stream.close()
                    Magic.set_magic(self.case, combined_stream.inode_id,
                                    "Combined stream")

                    map_stream.set_attribute(PYFLAG_REVERSE_STREAM, r_map_stream.urn)
                    r_map_stream.set_attribute(PYFLAG_REVERSE_STREAM, map_stream.urn)

                    ## FIXME - this needs to be done out of process!!!
                    Scanner.scan_inode(self.case, map_stream.inode_id,
                                       factories)
                    Scanner.scan_inode(self.case, r_map_stream.inode_id,
                                       factories)
                    Scanner.scan_inode(self.case, combined_stream.inode_id,
                                       factories)
                    

        ## Create a tcp reassembler if we need it
        processor = reassembler.Reassembler(packet_callback = Callback)

        ## Now process the file
        try:
            pcap_file = pypcap.PyPCAP(fd)
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

