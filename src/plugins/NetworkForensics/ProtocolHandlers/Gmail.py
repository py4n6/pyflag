# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Michael Cohen <scudette@users.sourceforge.net>
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
""" This module is designed to extract information from gmail traffic.

Basically gmail traffic is sent via javascript objects. The code is
evaluated dynamically so the data structures are not known. Its not
really valid JSON either. Previously we used an eval to try to parse
it but this has lots of problems especially when the data is corrupted
or truncated. We really needed a very forgiving parser to gloss over
data problems.

The way its implemented now is using the PyFlag Javascript
parser. This parser basically generates a DOM with javascript objects
(similar to an AST). We can then use regular DOM manipulation
algorithms to find what we need.

The following documents some of the protocol commands that I have seen:

Labels or mail boxes are marked with ^ e.g. ^i = inbox, ^all = all boxes

la - last activity:
    ['la', time, Access type. N = browser, IP address, ?, ?, ?,
     Timestamp, Last IP address, how long ago]

v - gmail version:
     ['v', major version. lang, minor version, hash]

ct - contact:
     ['ct' , proper name, email address, ?, ?]

ms - Message stream - this one is really complex:
     [ 'ms', unique message id, ?, ?, From name and email, from name, from email,
       sent time in ms, summary message, [list of labels], ?, Title,
       [ message_id,
           [ List of to receipients ], [ List of cc receipients], [ bcc receipients], ?,
           title,
           message, [ [ ## Now follows a list of attachments
                [ attachement_id, filename, content_type, size in bytes,
                  real attachement_id (this will be generated when posted eg - f_fas6ipsc0)
                  A placeholder image, content_type of placeholder,
                  link to thread attachement,
                  link to download attachement,
                  link to inline attachement (thumbnail),
                ] ] ]
           ?, ?
       ]
     ]

me - User's mail box:
      [ 'me', email address ]
     
"""
import pyflag.FlagFramework as FlagFramework
from pyflag.ColumnTypes import StringType, TimestampType, IntegerType, PacketType, guess_date
import FileFormats.urlnorm as urlnorm
import pyflag.DB as DB
import pyflag.Scanner as Scanner
import pyflag.Reports as Reports
import pyflag.FileSystem as FileSystem
import re, urllib
import pyflag.pyflaglog as pyflaglog
import pyflag.Time as Time
import LiveCom
import pdb
import FileFormats.Javascript as Javascript
import pyflag.Magic as Magic
import pyflag.CacheManager as CacheManager
import pyflag.aff4.aff4 as aff4
from pyflag.aff4.aff4_attributes import *

class GmailStreamMagic(Magic.Magic):
    """ Detect Gmail emails """
    type = "Gmail Stream"
    mime = "protocol/x-google-ajax"
    default_score = 20

    regex_rules = [
        ( "while(1);", (0,0)),
        ]

class GmailScanner(Scanner.GenScanFactory):
    """ Detect Gmail web mail sessions """
    depends = ['HTTPScanner']
    default = True
    group = 'NetworkScanners'
    service = "Gmail"
    url = None

    def make_link_from_query(self, fd, query):
        if not self.url:
            dbh = DB.DBO(fd.case)
            dbh.execute("select url from http where inode_id = %r limit 1", fd.inode_id)
            row = dbh.fetch()
            self.url = row['url'] or '?'
            try:
                self.url = self.url.split('?')[0]
            except IndexError: pass

        ## Normalise the url now
        url = "%s%s" % (self.url, query)
        
        return urlnorm.normalize(url)
        
    def ms(self, fd, root):
        """ This is the main message parsing command """
        result = dict(message_id = root[1],
                      From = root[4], type="Read",
                      service = self.service,
                      _sent = "from_unixtime(%d)" % (root[7]/1000))

        message_urn = "/Webmail/%s/%s" % (self.service,
                                          str(result['message_id']).replace("/","_"))
        
        ## Make sure we dont have duplicates of the same message -
        ## duplicates may occur in other connections, so we check
        ## the webmail table for the same yahoo message id
        fsfd = FileSystem.DBFS(fd.case)
        try:
            if fsfd.lookup(path = message_urn):
                return
        except RuntimeError:
            pass

        message = root[12]
        result['To'] = ','.join([str(x) for x in message[1]])
        result['CC'] = ','.join([str(x) for x in message[2]])
        result['BCC'] = ','.join([str(x) for x in message[3]])
        result['subject'] = message[5]
        
        message_fd = CacheManager.AFF4_MANAGER.create_cache_data(
            fd.case, message_urn, data = message[6],
            inherited = fd.urn)

        message_fd.insert_to_table("webmail_messages",
                                   result)

        ## Now the attachments:
        for part in message[7][0]:
            message_fd.write("<html><body><table><tr><td><a href='%s'>"\
                             "<img src='%s' /></a></td><td>%s (%s)</td></tr>"\
                             "</table></body></html>" % (
                self.make_link_from_query(fd, part[8]),
                self.make_link_from_query(fd, part[7]),
                part[1], part[3],
                ))

        message_fd.close()

    def version(self, fd, root):
        ## FIXME - ideally we would like to have a templating system
        ## where we can derive the different object offsets based on
        ## the version.
        print "Gmail Version %s" % root[1]
        
    def __init__(self):
        self.dispatcher = {'ms': self.ms,
                           'v': self.version}
    
    def scan(self, fd, scanners, type, mime, cookie, scores=None, **args):
        if "javascript" in mime and scores.get('GmailStreamMagic',0) > 0:
            pyflaglog.log(pyflaglog.DEBUG,"Opening %s for Gmail processing" % fd.inode_id)

            ## Make a new parser
            j=Javascript.JSParser()
            j.parse_fd(fd)
            j.close()

            ## gmail stream consist of arrays. The first element of
            ## the array is the command name, then the rest of the
            ## array is the args for that command. We look for
            ## commands which we support (much of the commands are not
            ## relevant), and pass the entire array up to the handler.
            for x in j.root.search("Array"):
                try:
                    command = x.children[0]
                    assert command.name == 'string'
                    command = command.innerHTML()
                except: continue

                if command in self.dispatcher:
                    self.dispatcher[command](fd, x)
                
    class Scan:
        parser = None
        javascript = None
        service = "Gmail"

        def get_url(self, metadata):
            try:
                metadata['host']
                metadata['url']
                metadata['content_type']
            except KeyError:
                dbh = DB.DBO(self.case)
                dbh.execute("select content_type,url,host from http where inode_id=%r limit 1", self.fd.inode_id)
                row = dbh.fetch()
                if not row: return True

                metadata['url'] = row['url']
                metadata['host'] = row['host']
                metadata['content_type'] = row['content_type']

        def boring(self, data=''):
            return True
            #self.get_url(metadata)
            
            if metadata['host']=='mail.google.com' and \
                   metadata['url'].startswith("http://mail.google.com/mail/"):
                if metadata['content_type'].startswith("text/javascript"):
                    self.javascript = ''
                elif metadata['content_type'].startswith("text/html"):
                    self.parser =  HTMLParser(verbose=0)
                else:
                    return True

                return False

            return True

        def process(self, data):
            Scanner.StoreAndScanType.process(self, data)
            ## Feed our parser some more:
            if not self.boring_status:
                if self.javascript == None:
                    self.parser.feed(data)
                    ## Get all the tokens
                    while self.parser.next_token(True): pass
                else:
                    self.javascript += data
                     
        def external_process(self, fd):
            if self.process_send_message(fd) or self.process_readmessage(fd):
                pyflaglog.log(pyflaglog.DEBUG,"Opening %s for Gmail processing" % self.fd.inode)
            
        def process_send_message(self,fd):
            ## Check to see if this is a POST request (i.e. mail is
            ## sent to the server):
            dbh = DB.DBO(fd.case)
            dbh.execute("select `inode_id`,`key`,`value` from http_parameters where inode_id=%r", fd.inode_id)
            query = {}
            key_map = {}

            for row in dbh:
                query[row['key'].lower()] = row['value']
                key_map[row['key'].lower()] = row['inode_id']

            result = {'type':'Edit Sent'}
            for field, pattern in [('To','to'),
                                   ('From','from'),
                                   ('CC','cc'),
                                   ('Bcc', 'bcc'),
                                   ('Subject', 'subject'),
                                   ('Message', 'body')]:
                if query.has_key(pattern):
                    result[field] = query[pattern]

            if len(result.keys())<3: return False
            
            ## Fixme: Create VFS node for attachments
            message_id = self.insert_message(result, "webmail")
            
            ## Are there any attachments?
            for k in query.keys():
                if k.startswith("f_"):
                    ## Create an Inode for it:
                    dbh.execute("select mtime from inode where inode_id = %r" , self.fd.inode_id)
                    row = dbh.fetch()

                    new_inode = "thttp_parameters:inode_id:%s:value" % key_map[k]
                    
                    inode_id = self.ddfs.VFSCreate(self.fd.inode,
                                                   new_inode,
                                                   k, mtime = row['mtime'],
                                                   _fast = True)
                    
                    dbh.insert("webmail_attachments",
                               inode_id = message_id,
                               attachment = inode_id)

                    fd = self.ddfs.open(inode = "%s|%s" % (self.fd.inode, new_inode))
                    Scanner.scanfile(self.ddfs, fd, self.factories)

            return message_id

        def process_readmessage(self,fd):
            """ This one pulls out the read message from the AJAX stream.

            Gmail does not send the message in html, it send it as a
            javascript object. So we need to try to find these objects
            and then decode them.
            """
            ## We are looking for a json stream, its not html at
            ## all. Google encode this stream in two ways:
            
            ## 1) The first statement is while(1); so that a browser
            ## getting it as normal script (and hence running it) will
            ## lock up.

            ## 2) Nowhere in the page there is < character - this
            ## stops a html parser from reading any tags. All <
            ## characters are actually encoded in unicode as \u003c
            if not self.javascript or not self.javascript.startswith("while"):
                return False

            try:
                json = parse_json(self.javascript[self.javascript.find('[[['):])
                result = {'type':'Read', "Message":''}
            except Exception,e:
                print "Unable to parse %s as json stream: %s" % (self.fd.inode , e)
                return False

            for i in json[0]:
                ## Message index (contains all kinds of meta data)
                if i[0]=='mi':
                    result['From'] = gmail_unescape(i[7])
                    result['Subject'] = gmail_unescape(i[16])
                    #result['Sent'] = guess_date(gmail_unescape(i[15]))
                    result['Sent'] = Time.parse(gmail_unescape(i[15]), case=self.case, evidence_tz=None)
                    for x in i[9]:
                        try:
                            if x[0][0]=='me':
                                result['To'] = gmail_unescape(x[0][1])
                        except (IndexError, ValueError): pass
                        
                ## Message body
                elif i[0]=='mb':
                    result['Message'] += gmail_unescape(i[1])
                ## This is a single combined message:
                elif i[0]=='ms':
                    message = i[13]
                    try: result['From'] = gmail_unescape(i[4])
                    except IndexError: pass
                    
                    try:
                        to = message[1]
                        if type(to)==list:
                            to = ",".join(to)
                            
                        result['To'] = gmail_unescape(to)
                    except IndexError: pass
                    try: result['Subject'] = gmail_unescape(message[5])
                    except IndexError: pass
                    try: result['Message'] = gmail_unescape(message[6])
                    except IndexError: pass

            if len(result.keys()) > 2:
                message_id = self.insert_message(result, "webmail")

##                    try:
##                        attachment = message[7][0][0]
##                        url = gmail_unescape(attachment[8])

##                        ## Make a note of the attachment so we can
##                        ## try to resolve it later.
##                        dbh = DB.DBO(self.case)
##                        dbh.insert("live_message_attachments",
##                                   message_id = message_id,
##                                   url = url)
##                    except IndexError:
##                        pass

                return message_id

class GoogleDocs(Scanner.GenScanFactory):
    """ A scanner for google docs related pages """
    class Scan:
        service = "Google Docs"
        def boring(self, data=''):
            ## This string identifies this document as worth scanning
            if "var trixApp" in data:
                self.parser =  HTMLParser(verbose=0)
                return False

            return True

        def external_process(self, fd):
            self.parser.close()
            if self.process_view_document():
                pyflaglog.log(pyflaglog.DEBUG,"Opening %s for Google Document processing" % self.fd.inode)

        def process_view_document(self):
            result = {}
            ## Find the actions:
            for script in self.parser.root.search("script"):
                data = script.innerHTML()
                m = re.search('var\s+TX_name\s+=\s+"([^"]+)";', data)
                if m:
                    result['subject'] = m.group(1)

                m = re.search('var\s+TX_username\s+=\s+"([^"]+)";', data)
                if m: result['from'] = m.group(1)

                m = re.search('var\s+TX_emailAddress\s+=\s+"([^"]+)";', data)
                if m: result['to'] = m.group(1)

                m = re.search(r'trixApp.processAction\d+\("([^\n]+)"\);', data,
                              re.S| re.M)

                if m:
                    result['message'] = gmail_unescape(m.group(1))
                    open("/tmp/test.html","w").write(m.group(1))

            if result:
                return self.insert_message(result, "webmail")

## Unit tests:
import pyflag.pyflagsh as pyflagsh
import pyflag.tests as tests

class GmailTests(tests.ScannerTest):
    """ Tests Gmail Scanner """
    test_case = "PyFlagTestCase1"
    test_file = 'gmail.com2.pcap'
    subsystem = "EWF"
    fstype = "PCAP Filesystem"

    def test01GmailScanner(self):
        """ Test Gmail Scanner """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env,
                             command="scan",
                             argv=["*",                   ## Inodes (All)
                                   "GmailScanner", "YahooMailScan",
                                   "SquirrelMailScan", "HotmailScanner"
                                   ])                   ## List of Scanners
