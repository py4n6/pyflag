""" This module implements features specific for HTTP Processing """
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
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.Scanner as Scanner
import pyflag.DB as DB
import pyflag.FileSystem as FileSystem
import FileFormats.HTML as HTML
import re,time,cgi,Cookie,pdb, os.path
from pyflag.ColumnTypes import StringType, TimestampType, AFF4URN, IntegerType, PacketType, guess_date, PCAPTime
import pyflag.Time as Time
import pyflag.CacheManager as CacheManager
from pyflag.aff4.aff4_attributes import *
import pyflag.Scanner as Scanner
import pyflag.pyflaglog as pyflaglog
from pyflag.FlagFramework import make_tld
import zlib, gzip
import pyflag.Reports as Reports

class HTTP2Scanner(Scanner.GenScanFactory):
    """ Scan HTTP Streams """
    order = 2
    group = 'NetworkScanners'

    def scan(self, fd, factories, type, mime):
        if "HTTP Request stream" in type:
            forward_fd = fd
            reverse_urn = fd[PYFLAG_REVERSE_STREAM]
            dbfs = FileSystem.DBFS(fd.case)
            reverse_fd = dbfs.open(urn = reverse_urn)
            pyflaglog.log(pyflaglog.DEBUG,"Openning %s for HTTP" % fd.inode_id)

            self.parse(forward_fd, reverse_fd, factories)

    request_re = re.compile("(GET|POST|PUT|OPTIONS|PROPFIND) +([^ ]+) +HTTP/1\..",
                                     re.IGNORECASE)
    response_re = re.compile("HTTP/1\.. (\\d+) +", re.IGNORECASE)

    def read_headers(self, request, forward_fd):
        while True:
            line = forward_fd.readline()
            if not line or line=='\r\n':    
                return True

            tmp = line.split(':',1)
            try:
                request[tmp[0].lower().strip()] =tmp[1].strip()
            except IndexError:
                pass

    def read_request(self, request, forward_fd):
        """ Checks if line looks like a URL request. If it is, we
        continue reading the fd until we finish consuming the request
        (headers including post content if its there).

        We should be positioned at the start of the response after this.
        """
        line = forward_fd.readline()
        m=self.request_re.search(line)
        if not m: return False

        request['url']=m.group(2)
        request['method']=m.group(1)
        self.read_headers(request, forward_fd)

        return True
        
    def read_response(self, response, fd):
        """ Checks if line looks like a HTTP Response. If it is, we
        continue reading the fd until we finish consuming the
        response.

        We should be positioned at the start of the next request after this.
        """
        ## Search for something that looks like a response:
        while 1:
            line = fd.readline()
            if not line: return False
            
            m=self.response_re.search(line)
            if m: break

        response['HTTP_code']= m.group(1)
        self.read_headers(response, fd)
        
        return True

    def skip_body(self, headers, fd):
        """ Reads the body of the HTTP object depending on the values
        in the headers. This function takes care of correctly parsing
        chunked encoding. We return a new map representing the HTTP
        object.

        We assume that the fd is already positioned at the very start
        of the object. After this function we will be positioned at
        the end of this object.
        """
        fd = self.handle_encoding(headers, fd)
        try:
            ## Handle gzip encoded data
            if headers['content-encoding'] == 'gzip':
                fd.close()
                fd.seek(0)
                gzip_fd = gzip.GzipFile(fileobj = fd, mode='rb')
                http_object = CacheManager.AFF4_MANAGER.create_cache_fd(
                    fd.case, '/'.join((fd.urn, "decompressed")),
                    target = fd.urn, inherited = fd.urn)
                
                while 1:
                    data = gzip_fd.read(1024*1024)
                    if not data: break
                    
                    http_object.write(data)

                return http_object
        except KeyError: pass
        
        return fd

    def handle_encoding(self, headers, fd):        
        http_object = CacheManager.AFF4_MANAGER.create_cache_map(
            fd.case, '/'.join((os.path.dirname(fd.urn), "HTTP","%s" % fd.tell())),
            target = fd.urn, inherited = fd.urn)

        try:
            skip = int(headers['content-length'])
            http_object.write_from(fd.urn, fd.tell(), skip)
            fd.seek(skip, 1)
            return http_object
        except KeyError:
            pass

        ## If no content-length is specified maybe its chunked
        try:
            if "chunked" in headers['transfer-encoding'].lower():
                while True:
                    line = fd.readline()
                    try:
                        length = int(line,16)
                    except:
                        return http_object
                    
                    if length == 0:
                        return http_object

                    ## There is a \r\n delimiter after the data chunk
                    http_object.write_from(fd.urn, fd.tell(), length)
                    fd.seek(length+2,1)
                return http_object
        except KeyError:
            pass

        ## If the header says close then the rest of the file is the
        ## body (all data until connection is closed)
        try:
            if "close" in headers['connection'].lower():
                http_object.write_from(fd.urn, fd.tell(), fd.size - fd.tell())
        except KeyError:
            pass

        return http_object
        
    def parse(self, forward_fd, reverse_fd, factories):
        while True:
            request = { 'url':'/unknown_request_%s' % forward_fd.inode_id,
                        'method': 'GET' }
            response = {}
            parse = False
            
            ## Is this a request?
            if self.read_request(request, forward_fd):
                parse = True
                request_body = self.skip_body(request, forward_fd)
                if request_body.size > 0:
                    request_body.close()
                    Scanner.scan_inode(self.case, request_body.inode_id,
                                       factories)
                    
                    
            if self.read_response(response, reverse_fd):
                parse = True
                response_body = self.skip_body(response, reverse_fd)
                if response_body.size > 0:
                    ## Store information about the object in the http table:
                    response_body.insert_to_table("http",
                                                  dict(method = request.get('method'),
                                                       url = request.get('url'),
                                                       status = response.get('HTTP_code'),
                                                       content_type = response.get('content-type'),
                                                       useragent = request.get('user-agent'),
                                                       host = request.get('host'),
                                                       tld = make_tld(request.get('host',''))
                                                       )
                                                  )
                    response_body.close()
                    Scanner.scan_inode(self.case, response_body.inode_id,
                                       factories)
            if not parse: break

            
    def identify(self):
        offset = self.fd.tell()
        ## Currently the HTTP scanner needs both sides of the
        ## conversation to work properly. So we must have a request
        ## header. We try to resync if we are given a partial HTTP/1.1
        ## stream by looking ahead for a HTTP request. We check the
        ## first 1024 bytes.
        header = self.fd.read(1024)
        m = self.request_re.search(header)
        if m:
            self.fd.seek(offset+m.start())
            return True

        m = self.response_re.search(header)
        if m:
            self.fd.seek(offset+m.start())
            return True
            
        return False

class HTTPRequests(Reports.PreCannedCaseTableReports):
    family = 'Network Forensics'
    description = 'View URLs requested'
    name = '/Network Forensics/URLs'
    default_table = 'HTTPCaseTable'
    columns = ['Timestamp', 'URN', 'URL', 'InodeTable.Size', 'TLD']

## UnitTests:
import unittest
import pyflag.pyflagsh as pyflagsh
from pyflag.FileSystem import DBFS
import pyflag.tests as tests

class HTTPTests(tests.ScannerTest):
    """ Tests HTTP Scanner """
    test_case = "PyFlagTestCase"
    test_file = '/testimages/http.pcap'

    def test01HTTPScanner(self):
        """ Test HTTP Scanner """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env,
                             command="scan",
                             argv=["*",                   ## Inodes (All)
                                   "PCAPScanner",
                                   "HTTP2Scanner", "GZScan"
                                   ])                   ## List of Scanners
        dbh = DB.DBO(self.test_case)
        dbh.execute("select count(*) as total from http")
        row = dbh.fetch()
        print "Number of HTTP transfers found %s" % row['total']
        self.failIf(row['total']==0,"Count not find any HTTP transfers?")
