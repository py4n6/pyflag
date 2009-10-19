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

## AFF4 attributes for MSN sessions
MSN_SESSION_ID = PYFLAG_NS + "msn:session_id"
MSN_CLIENT_ID = PYFLAG_NS + "msn:client_id"

## Current sessions are kept alive here
MSN_SESSIONS = aff4.Store(kill_cb = lambda x: x.close())

class MessageType(AFF4URN):
    def display(self, value, row, result):
        fsfd = FileSystem.DBFS(self.case)
        fd = fsfd.open(inode_id = value)
        fd.seek(row['Offset'])
        data = fd.readline()
        data = data.split(":",3)[3]
        result.text(data)
        fd.close()
        
class MSNSessionTable(FlagFramework.CaseTable):
    """ Store information about decoded MSN messages """
    name = 'msn_session'
    columns = [ [ AFF4URN, {} ],
                [ IntegerType, dict(name = 'Offset', column='offset')],
                [ AFF4URN, dict(name = 'Stream', column = 'stream_id') ],
                [ IntegerType, dict(name = 'Stream Offset', column='stream_offset')],
                [ BigIntegerType, dict(name = 'Session ID', column='session_id') ],
                [ StringType, dict(name = 'Sender', column='sender')],
                [ StringType, dict(name = 'Recipient', column='recipient')],
                [ StringType, dict(name = 'Type', column='type')],
                [ IntegerType, dict(name = 'P2P File', column='p2p_file') ],
                ]
    extras = [ [ PacketType, dict(name = 'Packet', column='stream_offset',
                                  stream_column = 'stream_id') ],
               [ MessageType, dict(name = 'Message') ],
               ]

class ChatMessages(Reports.PreCannedCaseTableReports):
    args = { 'filter': ' "Type" = MESSAGE',
             'order':0, 'direction':1,
             '_hidden': [6]}
    family = 'Network Forensics'
    description = 'View MSN/Yahoo chat messages'
    name = "/Network Forensics/Communications/Chats/MSN"
    default_table = "MSNSessionTable"
    columns = ['Packet', 'URN', 'Type', "Sender", "Recipient", "Message", "Offset"]


class MSNScanner(Scanner.GenScanFactory):
    """ Collect information about MSN Instant messanger traffic """
    default = True
    group = 'NetworkScanners'
    depends = ['PCAPScanner']

    session_urn = None
    session_id = -1
    def make_session_fd(self, fd, session_id=None):
        ## Make a new URN for this session
        if not session_id:
            session_id = self.session_id
        else:
            self.session_id = session_id
            
        self.session_urn = self.session_urn or \
                           "%s/MSN_Session_%s" % (os.path.dirname(fd.urn), session_id)
        
        try:
            session_fd = MSN_SESSIONS[self.session_urn]
        except:
            session_fd = CacheManager.AFF4_MANAGER.create_cache_data(
                fd.case, self.session_urn,
                target = fd.urn,
                inherited = fd.urn)
            ## Fill in some defaults
            session_fd.client_id = None
            session_fd.session_id = session_id
            
            MSN_SESSIONS.add(self.session_urn, session_fd)

        return session_fd
        
    def scan(self, fd, scanners, type, mime, cookie):
        if "MSN" in type and fd.urn.endswith("forward"):
            pyflaglog.log(pyflaglog.DEBUG,"Openning %s for MSN" % fd.inode_id)
            dbfs = FileSystem.DBFS(fd.case)
            forward_fd = fd
            reverse_fd = dbfs.open(urn = "%s/reverse" % os.path.dirname(fd.urn))

            for fd in NetworkScanner.generate_streams_in_time_order(
                forward_fd, reverse_fd):
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
            session_id = items[-1]
            fd = self.make_session_fd(fd, session_id)
            
            ## Fill in some information
            fd.client_id = items[2]
            
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

        session_fd = self.make_session_fd(fd)
        sender = session_fd.client_id
        ct = ''
        while 1:
            line = fd.readline().strip()
            if not line: break

            header, value = line.split(":",1)
            header = header.lower()
            
            if header == 'typinguser':
                sender = value
            elif header == 'content-type':
                ct = value
                    
        data = fd.read(end - fd.tell())
        
        ## We only care about text messages here
        if len(data)>0 and 'text/plain' in ct:
            ## Lets find out the timestamp of this point
            session_fd.insert_to_table("msn_session",
                                       dict(session_id = session_fd.session_id,
                                            offset = session_fd.tell(),
                                            sender = sender,
                                            type = 'MESSAGE',
                                            stream_id = fd.inode_id,
                                            stream_offset = start))
            session_fd.write(DB.expand("%s %s %s: %s\n", (time.ctime(fd.current_packet.ts_sec),
                                                          sender_name, sender, data)).encode("utf8"))

    def insert_session_data(self, session_fd, sender, recipient, type, data=None):
        args =  dict(session_id = session_fd.session_id,
                     sender = sender,
                     offset = session_fd.tell(),
                     recipient = recipient,
                     type = type)

        if data:
            args['Message'] = data
            fd.write(data)
            
        session_fd.insert_to_table("msn_session", args)
        
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
class MSNEvents(FlagFramework.EventHandler):
    def exit(self, dbh, case):
        MSN_SESSIONS.flush()

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

        ## Flush the cache
        MSN_SESSIONS.flush()
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
