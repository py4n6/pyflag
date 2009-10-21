""" This module implements processing for MSN Instant messager traffic

Most of the information for this protocol was taken from:
http://www.hypothetic.org/docs/msn/ietf_draft.txt
http://www.hypothetic.org/docs/msn/client/file_transfer.php
http://www.hypothetic.org/docs/msn/notification/authentication.php

Further info from the MSNPiki (an MSN protocol wiki)

TODO: Further work to make this scanner compatible with the latest MSN
version (I believe this is version 11 at 20060531).

"""
# Michael Cohen <scudette@gmail.com>
#
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

import pyflag.conf
config=pyflag.conf.ConfObject()
from pyflag.Scanner import *
import struct,sys,cStringIO
import pyflag.DB as DB
import pyflag.Reports as Reports
import pyflag.pyflaglog as pyflaglog
import base64, posixpath
import urllib,os,time,datetime
from pyflag.ColumnTypes import StringType, TimestampType, AFF4URN, IntegerType, ColumnType, PCAPTime, PacketType, BigIntegerType
import pyflag.Scanner as Scanner
from pyflag.aff4.aff4_attributes import *
import pyflag.aff4.aff4 as aff4
import pyflag.CacheManager as CacheManager
import plugins.NetworkForensics.NetworkScanner as NetworkScanner
import pyflag.FileSystem as FileSystem
import FileFormats.HTML as HTML

class MessageType(AFF4URN):
    def display(self, value, row, result):
        fsfd = FileSystem.DBFS(self.case)
        fd = fsfd.open(inode_id = value)
        fd.seek(row['Offset'])
        data = fd.read(row['Length'])
        result.text(data)
        fd.close()
        
class MSNSessionTable(FlagFramework.CaseTable):
    """ Store information about decoded MSN messages """
    name = 'msn_session'
    columns = [ [ AFF4URN, {} ],
                [ TimestampType, dict(name='Timestamp', column='time')],
                
                ## These are used to store the message in the stream
                [ IntegerType, dict(name = 'Offset', column='offset')],
                [ IntegerType, dict(name = 'Length', column='length')],
                
                [ BigIntegerType, dict(name = 'Session ID', column='session_id') ],
                [ StringType, dict(name = 'Sender', column='sender')],
                [ StringType, dict(name = 'Recipient', column='recipient')],
                [ StringType, dict(name = 'Type', column='type')],
                #[ IntegerType, dict(name = 'P2P File', column='p2p_file') ],
                ]
    extras = [ [ PacketType, dict(name = 'Packet', column='stream_offset',
                                  stream_column = 'stream_id') ],

               ## Use the Stream offset and length to reconstruct the
               ## message
               [ MessageType, dict(name = 'Message') ],
               ]

class ChatMessages(Reports.PreCannedCaseTableReports):
    args = { 'filter': ' "Type" = MESSAGE',
             'order':0, 'direction':1,
             '_hidden': [5,6]}
    family = 'Network Forensics'
    description = 'View MSN/Yahoo chat messages'
    name = "/Network Forensics/Communications/Chats/MSN"
    default_table = "MSNSessionTable"
    columns = ['Timestamp', 'Message', 'Type', "Sender", "Recipient", "Offset","Length"]


class MSNScanner(Scanner.GenScanFactory):
    """ Collect information about MSN Instant messanger traffic """
    default = True
    group = 'NetworkScanners'
    depends = ['PCAPScanner']
        
    def scan(self, fd, scanners, type, mime, cookie, **args):
        if "MSN" in type and fd.urn.endswith("forward"):
            pyflaglog.log(pyflaglog.DEBUG,"Openning %s for MSN" % fd.inode_id)
            dbfs = FileSystem.DBFS(fd.case)
            self.forward_fd = fd
            self.reverse_fd = dbfs.open(urn = "%s/reverse" % os.path.dirname(fd.urn))

            ## Make back references to each other
            self.forward_fd.reverse = self.reverse_fd
            self.reverse_fd.reverse = self.forward_fd

            ## Install defaults
            self.forward_fd.client_id =  self.reverse_fd.client_id = ''
            self.forward_fd.dest_id = self.reverse_fd.dest_id = ''
            
            self.session_id = -1

            for fd in NetworkScanner.generate_streams_in_time_order(
                self.forward_fd, self.reverse_fd):
                try:
                    line = fd.readline()
                    items = line.split()
                    command = items[0]
                except IndexError: continue

                ## Try to process the command
                try:
                    handler = getattr(self, command)
                except:
                    #print "Command %s not handled" % command
                    continue

                handler(items, fd, scanners)

            CacheManager.update_table_from_urn(fd.case, self.forward_fd.urn)
            CacheManager.update_table_from_urn(fd.case, self.reverse_fd.urn)

    def IRO(self, items, fd, scanners):
        """ List of current participants.
        
        IRO <transaction id> <number of this IRO> <total number of IRO that will be sent> <username> <display name>
        """
        self.forward_fd.dest_id = self.reverse_fd.client_id = items[4]

    def ANS(self, items, fd, scanners):
        """ Logs into the Switchboard session.

        We use this to store the current session ID and client_id (target username) for this entire TCP stream.

        ANS <transaction id> <account name> <auth string> <session id>
        
        e.g.
        ANS 1 name_123@hotmail.com 849102291.520491113 11752013

        Ignore these responses from the server:
        ANS 1854 OK
        """
        ## We are in the client -> server stream
        if len(items)==5:
            self.session_id = items[-1]
            ## Fill in some information
            fd.reverse.dest_id = fd.client_id = items[2]

            self.insert_session_data(fd, fd.client_id,
                                     "SWITCHBOARD SERVER",
                                     "TARGET JOINING_SESSION")


    def MSG(self, items, fd, scanners):
        """ Sends message to members of the current session

        There are two types of messages that may be sent:

        1) A message from the client to the message server. 
           This does not contain the nick of the client, but does contain a 
           transaction ID.  This message is sent to all users in the 
           current session.

        2) A message from the Switchboard server to the client contains 
           the nick of the sender.

        These two commands are totally different.

        1.

        MSG 1532 U 92
        MIME-Version: 1.0
        Content-Type: text/x-msmsgscontrol
        TypingUser: user@hotmail.com

        Format is: MSG <Transaction ID> <Type of ACK required> <length of message in bytes>

        Transaction ID is used to correlate server responses to client requests.

        2.

        MSG user2@hotmail.com I%20am%20so%20great 102
        MIME-Version: 1.0
        Content-Type: text/x-msmsgscontrol
        TypingUser: user2@hotmail.com

        Format is: MSG <Nick> <URL encoded displayname> <length of message in bytes>
        
        """
        length = int(items[-1])
        start = fd.tell()
        end = start + length

        if "@" in items[1]:
            ## Its type 2 (see above)
            sender_name = "(%s)" % HTML.url_unquote(items[2])
        else:
            ## Its type 1
            sender_name = ''

        sender = fd.client_id
        ct = ''
        while 1:
            line = fd.readline().strip()
            if not line: break

            header, value = line.split(":",1)
            header = header.lower()
            
            if header == 'typinguser':
                fd.client_id = fd.reverse.dest_id = value.strip()
            elif header == 'content-type':
                ct = value

        ## Update the start to be start start of this line
        start = fd.tell()
        fd.seek(end - start, 1)
        ## We only care about text messages here
        if end > start and 'text/plain' in ct:
            ## Lets find out the timestamp of this point
            CacheManager.urn_insert_to_table(fd.urn, "msn_session",
                      dict(session_id = self.session_id,
                           _time = "from_unixtime(%s)" % fd.current_packet.ts_sec,
                           offset = start,
                           length = end - start,
                           sender = fd.client_id,
                           recipient = fd.dest_id,
                           type = 'MESSAGE',
                           ))

    def insert_session_data(self, fd, sender, recipient, type, data=None):
        args =  dict(session_id = self.session_id,
                     _time = "from_unixtime(%s)" % fd.current_packet.ts_sec,
                     sender = sender,
                     offset = fd.tell(),
                     recipient = recipient,
                     type = type)
            
        CacheManager.urn_insert_to_table(fd.urn, "msn_session", args)
        
## MSN streams look a lot like RFC2822 sometimes:
import pyflag.Magic as Magic

class MSNStreamMagic(Magic.Magic):
    """ Detect MSN Streams """
    type = "MSN Stream"
    mime = "protocol/x-msn-messanger"
    default_score = 20

    regex_rules = [
        ( "USR \d+ OK [^@]+@[^@]+", (0,1000)),
        ( "\nCAL \d+ RINGING \d+", (0,1000)),
        ( "\nACK \d+", (0,1000)),
        ( "\nTypingUser:", (0,1000)),
        ( "\nMSG ", (0,1000)),
        ( "\nUser-Agent: ", (0,1000)),
        ( "VER \d+ MSN", (0,10)),
        ( "\nCVR \d+", (0,100)),
        ( "\nPNG", (0,100)),
        ( "OUT OTH", (0,100)),
        ]

    samples = [
        (100, \
"""USR 1 OK foo004470@hotmail.com foobar
CAL 2 RINGING 17528774
JOI user022714@hotmail.com gumby
ACK 3
MSG user022714@hotmail.com gumby 95
MIME-Version: 1.0
Content-Type: text/x-msmsgscontrol
TypingUser: user022714@hotmail.com
""")]


## Ensure we flush the MSN cache when needed
#class MSNEvents(FlagFramework.EventHandler):
#    def exit(self, dbh, case):
#        MSN_SESSIONS.flush()

## UnitTests:
import unittest
import pyflag.pyflagsh as pyflagsh
from pyflag.FileSystem import DBFS
import pyflag.tests

class MSNTests(pyflag.tests.ScannerTest):
    """ Tests MSN Scanner (Ver 8) """
    # We pick an obscure name on purpose
    test_case = "PyFlagTestCase"
    test_file = "/NetworkForensics/ProtocolHandlers/MSN/MSN_Cap1_Ver8_LoginWithMessages.pcap"

    ## Test protocol version 8 handling...
    def test01Scan(self):
        """ Scan for MSN Messages """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env,
                             command="scan",
                             argv=["*",                   ## Inodes (All)
                                   "MSNScanner"
                                   ])                   ## List of Scanners

        ## What should we have found?
        dbh = DB.DBO(self.test_case)
        dbh.execute("""select count(*) as total from `msn_session` where type=\"MESSAGE\"""")
        row = dbh.fetch()
        print row
        assert row['total'] == 10

        ## We should also find user information  
        ## For example, check we pulled out the user's OS.
        dbh.execute("""select user_data from `msn_users` where """\
                    """user_data_type=\"os\" and packet_id=19""")
        row=dbh.fetch()
        assert row["user_data"] == "winnt 5.1 i386"
