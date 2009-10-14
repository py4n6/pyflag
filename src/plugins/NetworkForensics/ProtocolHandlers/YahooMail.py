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
import pyflag.ColumnTypes as ColumnTypes
import pyflag.FileSystem as FileSystem
import pyflag.FlagFramework as FlagFramework
import pyflag.ColumnTypes as ColumnTypes
import pyflag.Time as Time
import pyflag.aff4.aff4 as aff4
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
    

class YahooMagic(Magic.Magic):
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
    
class YahooMailScan(LiveCom.HotmailScanner):
    """ Detect YahooMail Sessions """

    class Scan(LiveCom.HotmailScanner.Scan):
        service = "Yahoo"
        
        def boring(self, data=''):
            ## We dont think its boring if our base class does not:
            ## And the data contains '<title>\s+Yahoo! Mail' in the top.
            if not Scanner.StoreAndScanType.boring(self, data=''):
                m=re.search("<title>[^<]+Yahoo! Mail", data)
                if m:
                    self.username = None
                    ## Make a new parser:
                    if not self.parser:
                        self.parser =  HTML.HTMLParser(verbose=0)
                    return False

            return True

        def external_process(self, fd):
            pyflaglog.log(pyflaglog.DEBUG,"Opening %s for YahooMail processing" % self.fd.inode)

            ## Try to determine the username:
            try:
                title = self.parser.root.find("title").children[0]
                m = re.search("[^@ ]+@[^ ]+", title)
                if m:
                    self.username = m.group(0)
            except:
                pass

            ## Find out what kind on message this is:
            self.process_readmessage(fd) or \
                  self.process_mail_listing() or \
                  self.process_edit_read() or \
                  self.process_send_message(fd) or\
                  self.process_main_page()
                                         
        def process_edit_read(self):
            """ Process when an edit box is read from the server """
            root = self.parser.root
            result = {}
            for field, tag, pattern in [('To','textarea','tofield'),
                                        ('CC','textarea','ccfield'),
                                        ('Bcc','textarea', 'bccfield'),
                                        ('Subject', 'input', 'subjectfield')]:
                tmp = root.find(tag, {'id': pattern})
                if tmp:
                    try:
                        result[field] = HTML.decode_entity(tmp.children[0])
                    except IndexError:
                        pass

            ## Find the message:
            tmp = root.find('input', {'name':'PlainMsg'})
            if tmp:
                message = HTML.decode_entity(tmp['value'])
                if message:
                    result['message'] = message

            if result:
                result['type']='Edit Read'
                if self.username:
                    result['From'] = self.username
                
                return self.insert_message(result, inode_template="y%s")

        def process_main_page(self):
            """ Search for a main page """
            result = {'type': 'Front Page'}
            if self.parser.root.find("div",{"class":"toptitle"}):
                result['message'] = "Front Page"

            return self.insert_message(result, inode_template = "y%s")
        
        def process_mail_listing(self):
            """ This looks for the listing in the mail box """
            table = self.parser.root.find("table",{"id":"datatable"})
            if not table: return False
            result = {'type': 'Listed', 'message': table}

            mail_box = self.parser.root.find("h2", {"id":"folderviewheader"})
            if mail_box:
                result['From'] = mail_box.innerHTML()

            if self.username:
                result['To'] = self.username

            return self.insert_message(result, inode_template = "y%s")

        def process_send_message(self,fd):
            dbh = DB.DBO(self.case)
            dbh.execute("select `key`,`value` from http_parameters where inode_id = %r", self.fd.inode_id)
            query = dict([(r['key'].lower(),r['value']) for r in dbh])
            result = {'type':'Edit Sent'}
            if self.username:
                result['From'] = self.username

            for field, pattern in [('To','send_to'),
                                   ('From','username'),
                                   ('CC','send_to_cc'),
                                   ('Bcc', 'send_to_bcc'),
                                   ('subject', 'subject'),
                                   ('message', 'body'),

                                   ## These apply for Yahoo Versions after 20080424:
                                   ('Message', 'content'),
                                   ('To', 'to'),
                                   ('CC', 'cc'),
                                   ('Bcc','bcc'),
                                   ('From','deffromaddress'),
                                   ('subject', 'subj'),
                                   ('message_id', 'ym.gen'),
                                   ]:
                if query.has_key(pattern):
                    result[field] = query[pattern]

            if len(result.keys())<=3: return False

            new_inode_id = self.insert_message(result,inode_template="y%s")

            ## Do attachments:
            dbh.execute("select * from http_parameters where inode_id = %r and `key` like 'userFile%%'", self.fd.inode_id)
            inodes = [ row['indirect'] for row in dbh if row['indirect'] ]
            for inode in inodes:
                if new_inode_id > 1:
                    dbh.insert('webmail_attachments',
                               inode_id = new_inode_id,
                               attachment = inode)
                
            return True

        def process_readmessage(self, fd):
            result = {'type': 'Read', 'message':'' }

            dbh = DB.DBO(self.case)
            dbh.execute("select value from http_parameters where inode_id = %r and `key`='MsgId'", self.fd.inode_id)
            row = dbh.fetch()
            if row:
                result['message_id'] = row['value']

            ## Try to find the messageheader
            header = self.parser.root.find("table", {"class":"messageheader"})
            if header: return self.process_message_yahoo1(result, header)
            
            header = self.parser.root.find("div", {"class":"msgheader"})
            if header: return self.process_message_yahoo2(result, header)

        def process_message_yahoo2(self, result, header):
            try:
                result['subject'] = header.find(".", {"id":"message_view_subject"}).innerHTML()
            except AttributeError: pass

            try:
                date = header.find("div", {"id":"message_view_date"}).innerHTML()
                #result['sent'] = ColumnTypes.guess_date(date).__str__()
                result['sent'] = Time.parse(date, case=self.case, evidence_tz=None)
            except AttributeError: pass

            context = None
            for div in header.search("div"):
                try:
                    cls = div.attributes['class']
                except KeyError: continue

                if cls == "details" and context:
                    if context not in result:
                        result[context] = div.innerHTML()
                    context = None

                if cls == "label":
                    a = div.innerHTML().strip()
                    if a.startswith("To:"):
                        context = "To"
                    elif a.startswith("From:"):
                        context = "From"
                        
            result['message'] = header.innerHTML()

            return self.insert_message(result, inode_template = "y%s")
            
        def process_message_yahoo1(self, result, header):
            """ Handle Yahoo mail from old version (prior to 20080224) """
            ## Look through all its rows:
            context = None
            for td in header.search("td"):
                if context:
                    for i in td:
                        if type(i)==str:
                            result[context] = HTML.unquote(HTML.decode_entity(i))
                            break
                    context = None

                data = td.innerHTML()
                if data.lower().strip().startswith('from:'):
                    context = 'From'
                elif data.lower().strip().startswith('to:'):
                    context = 'To'
                elif data.lower().strip().startswith('date:'):
                    context = 'Sent'
                elif data.lower().strip().startswith('subject:'):
                    context = 'Subject'

            ## Now the message:
            msgbody = self.parser.root.find('div', {"class":"msgbody"})
            if msgbody:
                result['message'] = msgbody.innerHTML()
                
            if 'Sent' in result:
                #result['Sent'] = ColumnTypes.guess_date(result['Sent'])
                result['sent'] = Time.parse(result['sent'], case=self.case, evidence_tz=None) 

            ## Find the message id:
            tag = header.find('input', dict(name='MsgId'))
            if tag:
                result['message_id'] = tag['value']

            if len(result.keys())>3:
                return self.insert_message(result, inode_template = "y%s")

class YahooMail20Scan(YahooMailScan):
    """ A Scanner for Yahoo Mail 2.0 (AJAX) """
    service = "YahooMail AJAX"

    def fixup_page(self, result, tag_class):
        """ Its not really possible to represent AJAX communications
        properly, so we just write the message here.

        FIXME - It may be possible to render the page by inserting the
        message into a template created by other pages.
        """
        message = result.get('message','')
        return message

    def scan(self, fd, factories, type, mime):
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
            fsfd = FileSystem.DBFS(self.case)
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

            ## now iterate over all the parts:
            message_fd = CacheManager.AFF4_MANAGER.create_cache_data(
                fd.case, message_urn, 
                inherited = fd.urn)
            
            message_fd.insert_to_table("webmail_messages",
                                       result)

            message_fd.close()
            
            for part in message.search("part"):
                #pdb.set_trace()
                ## Parts basically message attachments.
                ct = part.attributes['type']
                part_number = part.attributes['partid']
                part_urn = "/".join((message_urn, part_number))

                ## Usually text/html are the main body
                data = None
                if "text" in ct:
                    text = part.find("text")
                    data = HTML.unquote(HTML.decode_entity(text.innerHTML()))
                elif "image" in ct:
                    data = DB.expand("<b>%s</b><br><img src='%s'/>",(
                        HTML.url_unquote(part.attributes.get('filename','')),
                        HTML.url_unquote(part.attributes['thumbnailurl'])))
                    
                if data:
                    ## Put the data in its own part - the part
                    ## inherits from the message which in turn
                    ## inherits from the HTTP stream. This way we
                    ## implicitly have the URL attached to this
                    ## URN. This is needed when rendering the part (in
                    ## case its html).
                    part_fd = CacheManager.AFF4_MANAGER.create_cache_data(
                        fd.case, part_urn,
                        inherited = message_fd.urn,
                        data = data)
                    
                    part_fd.close()

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
