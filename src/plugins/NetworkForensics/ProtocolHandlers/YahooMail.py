# ******************************************************
# Copyright 2008: Commonwealth of Australia.
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
""" This module will retrieve the email messages from Yahoo mail """
import pyflag.DB as DB
import LiveCom, pdb
import pyflag.pyflaglog as pyflaglog
import pyflag.Scanner as Scanner
import re
import FileFormats.HTML as HTML
import FileFormats.urlnorm as urlnorm
import pyflag.ColumnTypes as ColumnTypes
import pyflag.FileSystem as FileSystem
import pyflag.FlagFramework as FlagFramework
import pyflag.ColumnTypes as ColumnTypes
import pyflag.Time as Time
import pyflag.Magic as Magic
import pyflag.CacheManager as CacheManager

class YahooMagic(Magic.Magic):
    """ Identify Yahoo Classic Mail Messages """
    type = "Yahoo Mail Classic"
    mime = "protocol/x-yahoomail-classic"
    default_score = 100

    regex_rules = [
        ( "Yahoo! Mail", (0,200)),
        ]
    
class YahooMagicAJAX(Magic.Magic):
    """ Identify Yahoo Mail AJAX Edition """
    type = "Yahoo Mail AJAX"
    mime = "protocol/x-yahoomail-ajax"
    default_score = 100

    regex_rules = [
        ( "<GetDisplayMessageResponse", (0,200)),
        ( "<SendMessageResponse", (0,200)),
        ( "<ListMessagesResponse", (0,200)),
        ( "<SetMetaDataResponse", (0,200)),
        ( "<GetAttachmentSettingsResponse", (0,200)),
        ]

class YahooMail20Scan(LiveCom.HotmailScanner):
    """ A Scanner for Yahoo Mail 2.0 (AJAX) """
    service = "YahooMail AJAX"

    def scan(self, fd, scanners, type, mime, cookie, **args):
        if "Yahoo Mail AJAX" in type:        
            self.parser =  HTML.HTMLParser(verbose=0)
            pyflaglog.log(pyflaglog.DEBUG,"Opening %s for YahooMail2.0 processing" %
                          fd.inode_id)

            ## Read all the data into the parser
            self.context = None
            while 1:
                data = fd.read(1024*1024)
                if not data: break

                if not self.context: self.context = data
                self.parser.feed(data)

            self.parser.close()

            if 'GetDisplayMessageResponse' in self.context:
                self.process_readmessage(fd)
            #elif self.context=='ListMessagesResponse':
            #    self.process_mail_listing(fd)
            #elif self.context=='SendMessageResponse':
            #    self.process_send_message(fd)

    def process_send_message(self, fd):
        dbh = DB.DBO(self.case)
        dbh.execute("select `key`,`value`,`indirect` from http_parameters where `key`='body' and inode_id = %r limit 1", self.fd.inode_id)
        row = dbh.fetch()
        if not row: return

        inode_id = row['indirect']
        if not inode_id: return

        ## Need to parse the sent message
        fsfd = FileSystem.DBFS(self.case)
        fd = fsfd.open(inode_id = inode_id)
        self.parser =  HTML.HTMLParser(verbose=0)
        self.parser.feed(fd.read())
        self.parser.close()
        root = self.parser.root

        result = {'type':'Edit Sent'}
        result['From'] = self.parse_email_address(root, 'from')
        result['To'] = self.parse_email_address(root, 'to')
        try:
            result['message'] = root.find("text").innerHTML()
        except: pass

        ## Sometimes they also give us the html version
        #try:
        #    result['message'] = root.find("html").innerHTML()
        #except: pass

        try:
            result['subject'] = root.find("subject").innerHTML()
        except: pass

        self.insert_message(result, "webmail")

    def parse_email_address(self, message, tag):
        from_tag = message.find(tag)
        if from_tag:
            try:
                name = from_tag.find("name").innerHTML()
            except: name = ''

            email = HTML.unquote(HTML.decode_entity(from_tag.find("email").innerHTML()))
            return "%s <%s>" % (name, email)                    

    def process_mail_listing(self):
        result = {'type': 'Listed', 'message': ''}
        root = self.parser.root
        folder = root.find("folderinfo")
        if not folder: return
        result['from'] = folder.innerHTML()

        listing = "<table><tr><th>From</th><th>To</th><th>Subject</th><th>Received</th></tr>"
        for message in root.search("messageinfo"):
            from_tag = message.find("from")

            listing += "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n" % (
                self.parse_email_address(message, 'from'),
                message.attributes.get("toemail"),
                message.attributes.get("subject"),
                Time.parse(message.attributes.get("receiveddate")),
                )

        listing += "<table>"

        result['message'] = listing

        self.insert_message(result, "webmail")

    def process_readmessage(self,fd):
        ## This is what the message tree looks like (XML):
        ## <GetDisplayMessageResponse>
        ##   <message>
        ##     <header>
        ##     <part>
        ##     <part>
        ##   <message>
        ##   <message>

        ## Each message is a seperate message - therefore the same
        ## HTTP object might relay several messages.
        root = self.parser.root
        for message in root.search('message'):
            result = {'type': 'Read', 'service':self.service }
            result['message_id'] = message.find("mid").innerHTML()

            ## Messages are made unique using the message_id. This
            ## ensures that even if the same message was seen multiple
            ## times in the traffic, we only retain one copy of it.
            message_urn = "/Webmail/%s/%s" % (self.service,
                                              result['message_id'].replace("/","_"))

            ## Make sure we dont have duplicates of the same message -
            ## duplicates may occur in other connections, so we check
            ## the webmail table for the same yahoo message id
            fsfd = FileSystem.DBFS(fd.case)
            try:
                if fsfd.lookup(path = message_urn):
                    continue
            except RuntimeError:
                pass
            
            try:
                result['sent'] = Time.parse(message.find("receiveddate").innerHTML())
            except: pass

            result['subject'] = HTML.unquote(HTML.decode_entity(
                message.find("subject").innerHTML()))
            for tag,field in [('from','From'),
                              ('to','To')]:
                result[field] = self.parse_email_address(message, tag)

            message_fd = CacheManager.AFF4_MANAGER.create_cache_data(
                fd.case, message_urn, 
                inherited = fd.urn)
            
            message_fd.insert_to_table("webmail_messages",
                                       result)
            
            ## now iterate over all the parts:            
            for part in message.search("part"):
                ## Parts are basically message attachments.
                ct = part.attributes['type']
                part_number = part.attributes['partid']
                part_urn = "/".join((message_urn, part_number))

                ## Usually text/html are the main body
                data = None
                if "text" in ct:
                    text = part.find("text")
                    message_fd.write(HTML.unquote(HTML.decode_entity(text.innerHTML())))
                elif "image" in ct:
                    message_fd.write(DB.expand("<b>%s</b><br><img src='%s'/>",(
                        self.make_link(part.attributes.get('filename','')),
                        self.make_link(part.attributes['thumbnailurl']))))

            message_fd.close()

    def make_link(self, url):
        return urlnorm.normalize(HTML.unquote(url))


import pyflag.tests as tests
import pyflag.pyflagsh as pyflagsh

class YahooMail20Tests(tests.ScannerTest):
    """ Test YahooMail20 Scanner """
    test_case = "PyFlagTestCase"
    test_file = "yahoomail_simple_2.pcap"

    def test01YahooMailScanner(self):
        """ Test Scanner """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env,
                             command="scan",
                             argv=["*",                   ## Inodes (All)
                                   "YahooMail20Scan", "YahooMailScan",
                                   ])                   ## List of Scanners
    def XXXtearDown(self):
        print "Closing volume"
        CacheManager.AFF4_MANAGER.close(self.test_case)
