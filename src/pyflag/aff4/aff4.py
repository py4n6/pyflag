#!/usr/bin/python
""" This module implements the Advaced Forensics File Format 4 (AFF4).

The module is divided into two parts, the first is the low level
interface to AFFObject objects. These objects form the basic building
blocks for all AFF4 components.

The high level interface contains an API for putting the low level
components together into high level constructs which are usable in
practice. This makes it easy to prepare commonly used components. The
high level API consists of functions with optional parameters where
callers can tune the required behaviour.

The high level interface is simply a convenience API and uses the low
level interface itself. Its possible to achieve everything with the
low level API alone.
"""
import uuid, posixpath, hashlib, base64, bisect
import urllib, os, re, struct, zlib, time, sys
import StringIO
import threading, mutex
import pdb
import textwrap, os.path, glob

ZIP64_LIMIT = (1<<31) - 1
ZIP_FILECOUNT_LIMIT = 1 << 16
ZIP_STORED = 0
ZIP_DEFLATED = 8

structCentralDir = "<4s4B4HL2L5H2L"
stringCentralDir = "PK\001\002"
structEndArchive64 = "<4sQ2H2L4Q"
stringEndArchive64 = "PK\x06\x06"
structEndArchive = "<4s4H2LH"
stringEndArchive = "PK\005\006"
structFileHeader = "<4s2B4HL2L2H"
stringFileHeader = "PK\003\004"
sizeFileHeader = struct.calcsize(structFileHeader)
structEndArchive64Locator = "<4sLQL"
stringEndArchive64Locator = "PK\x06\x07"
sizeEndCentDir64Locator = struct.calcsize(structEndArchive64Locator)

#from zipfile import ZIP_STORED, ZIP_DEFLATED, ZIP64_LIMIT, structCentralDir, stringCentralDir, structEndArchive64, stringEndArchive64, structEndArchive, stringEndArchive, structFileHeader

from aff4_attributes import *

## This is a dispatch table for different volume handlers. When a
## volume is opened, we try each handler in turn.
VOLUME_DISPATCH = []

## Some verbosity settings
_DEBUG = 10
_DETAILED = 7
_INFO = 5
_WARNING = 1

## This dict specifies objects and attributes which will not be
## serialised into the properties file. These attributes are
## automatically generated from other means (for example the zip file
## headers).
NON_SERIALIZABLE_OBJECTS = {
    AFF4_SEGMENT : [ AFF4_TYPE, AFF4_SIZE,
                     AFF4_INTERFACE, AFF4_INTERFACE,
                     AFF4_STORED, AFF4_TIMESTAMP
                     ],
    }

## Bootstap DEBUG function (only add this after loading this module -
## see below)
def DEBUG(verb, fmt, *args):
    pass

import urllib

def fully_qualified_name(filename, context_name):
    """ Converts filename into a fully_qualified_name relative to the
    context_name. If filename is already a fully_qualified_name, do
    nothing.
    """
    if "://" in filename: return filename
    
    if not filename.startswith(FQN):
        filename = "%s/%s" % (context_name, filename)

    return posixpath.normpath(filename)

def relative_name(filename, context_name):
    """ Returns a relative name to the supplied context. (ie. if the
    name begins with context, strip the context off it.
    """
    if filename.startswith(context_name):
        return filename[len(context_name)+1:]

    return filename

def smart_string(data):
    if type(data)==str: return data

    return data.encode("utf8","ignore")

def b64_encode(data):
    """ A convenience function to base64 encode with no line breaks """
    result = data.encode("base64").splitlines()
    return ''.join(result)

int_re = re.compile("(\d+)([kKmMgGs]?)")
def parse_int(string):
    """ Parses an integer from a string. Supports suffixes """
    try:
        m = int_re.match(string)
    except TypeError:
        return int(string)
    
    if not m: return NoneObject("string %r is not an integer" % string)

    base = int(m.group(1))
    suffix = m.group(2).lower()

    if not suffix:
        return base

    if suffix == 's':
        return base * 512

    if suffix == 'k':
        return base * 1024

    if suffix == 'm':
        return base * 1024 * 1024

    if suffix == 'g':
        return base * 1024 * 1024 * 1024

    return NoneObject("Unknown suffix '%r'" % suffix)

def read_with_default(uri, attribute, default):
    result = oracle.resolve(uri, attribute)
    if isinstance(result,NoneObject):
        result = default
        oracle.set(uri, attribute, default)

    return result

class NoneObject(object):
    """ A magical object which is like None but swallows bad
    dereferences, __getattribute__, iterators etc to return itself.

    Instantiate with the reason for the error.
    """
    def __init__(self, reason, strict=False):
        DEBUG(_DEBUG, "Error: %s" % reason)
        self.reason = reason
        self.strict = strict
        if strict:
            self.bt = get_bt_string()

    def __str__(self):
        ## If we are strict we blow up here
        if self.strict:
            result = "Error: %s\n%s" % (self.reason, self.bt)
            print result
            sys.exit(0)
        else:
            return "Error: %s" % (self.reason)

    ## Behave like an empty set
    def __iter__(self):
        return self

    def next(self):
        raise StopIteration()

    def __getattribute__(self,attr):
        try:
            return object.__getattribute__(self, attr)
        except AttributeError:
            return self

    def __bool__(self):
        return False

    def __nonzero__(self):
        return False

    def __eq__(self, other):
        return False

    ## Make us subscriptable obj[j]
    def __getitem__(self, item):
        return self

    def __add__(self, x):
        return self

    def __sub__(self, x):
        return self

    def __int__(self):
        return 0

    def __call__(self, *arg, **kwargs):
        return self

def Raise(reason):
    raise RuntimeError(reason)

class AFFObject(object):
    """ All AFF4 objects extend this one.

    Object protocol
    ===============

    AFFObjects are created via two mechanisms:

    1) The oracle.open(urn) method is called with the explicit
    URN. This will call the constructor and pass this URN. The object
    is then expected to initialise using various attributes of the URN
    from the universal resolver (e.g. AFF4_STORED to find its backing
    object etc).

    2) When an object is created for the first time (and does not
    already exist in the resolver) it does not have a known URN. In
    this case the following protocol is followed:

       a) Create a new instance of the object - by passing None to the
       URN it is expected to generate a new valid URN:

          obj = AFFObjects() 

       b) Now obj.urn is a new valid and unique URN. We set all
       required properties:

          oracle.set(obj.urn, AFF4_STORED, somewhere)
          oracle.set(obj.urn, AFF4_CERT, ...)
          etc.

       c) Now call the finish method of the object to complete
       it. This method should check that all required parameters were
       provided, set defaults etc.

          obj.finish()

       Once the finish() method is called the object is complete and
       is the same as that obtained from method 1 above.

    Thread protocol
    ===============

    AFFObjects are always managed via the universal resolver. This
    means that they must be returned to the resolver after we finish
    using them. Obtaining an object via oracle.open() actually locks
    the object so other threads can not acquire it until it is
    returned to the oracle. Failing to return the object will result
    in thread deadlocks.

    For example, the following pattern must be used:

    fd = oracle.open(urn, 'r')
    try:
        ## do stuff with the fd
    finally:
        oracle.cache_return(fd)

    Your thread will hold a lock on the object between the try: and
    finally. You must not touch the object once its returned to the
    oracle because it may be in use by some other thread (although
    fd.urn is not going to change so its probably ok to read it). You
    must ensure that the object is returned to the cache as soon as
    possible to avoid other threads from blocking too long.
    """
    urn = None
    mode = 'r'
    
    def __init__(self, urn=None, mode='r'):
        self.urn = urn or "%s%s" % (FQN, uuid.uuid4())
        self.mode = mode

    def set_attribute(self, attribute, value):
        oracle.set(self.urn, attribute, value)
        
    def finish(self):
        """ This method is called after the object is constructed and
        all properties are set.
        """
        pass

    def __str__(self):
        return "<%s: %s instance at 0x%X>" % (self.urn, self.__class__.__name__, hash(self))

    def explain(self):
        stored = oracle.resolve(self.urn, AFF4_STORED)
        result = "Stream %s %s:\n   %s" % (
            self.__class__.__name__,
            self.urn,
            "\n   ".join(oracle.export(self.urn).splitlines()))

        result += "\n\n* "

        if stored:
            ## Now explain the stored URN
            try:
                fd = oracle.open(stored, 'r')
            except: return result
            try:
                result += "\n ".join(fd.explain().splitlines())
            finally:
                oracle.cache_return(fd)

        return result

    def close(self):
        pass

    def set_inheritence(self, inherited):
        oracle.add(self.urn, AFF4_INHERIT, inherited)

#     def close(self):
#         if oracle.resolve(GLOBAL, CONFIG_PROPERTIES_STYLE) == 'combined': return

#         ## Write the properties file
#         container = oracle.resolve(self.urn, AFF4_STORED)
#         volume = oracle.open(container,'w')
#         try:
#             volume.writestr(fully_qualified_name("properties", self.urn),
#                             oracle.export(self.urn),
#                             compress_type = ZIP_DEFLATED)
#         finally:
#             oracle.cache_return(volume)
            

class AFFVolume(AFFObject):
    """ A Volume simply stores segments """
    def load_from(self, urn):
        """ Load the volume from urn. urn must be a Stream Object """

class FileLikeObject(AFFObject):
    readptr = 0
    mode = 'r'
    data = None

    def __init__(self, urn=None, mode='r'):
        AFFObject.__init__(self, urn, mode)
        if mode=='r':
            self.size = parse_int(oracle.resolve(self.urn, AFF4_SIZE)) or 0
        else:
            self.size = 0

    def seek(self, offset, whence=0):
        if whence == 0:
            self.readptr = offset
        elif whence == 1:
            self.readptr += offset
        elif whence == 2:
            self.readptr = self.size + offset

    def read(self, length):
        pass

    def write(self, data):
        pass

    def tell(self):
        return self.readptr

    def get_data(self):
        if not self.data:
            self.seek(0)
            self.data = self.read(self.size)
            
        return self.data

    def truncate(self, offset):
        pass

    def close(self):
        pass

def escape_filename(filename):
    """ Escape a URN so its suitable to be stored in filesystems.

    Windows has serious limitations of the characters allowed in
    filenames, so we need to escape them whenever we store segments in
    files.
    """
    return urllib.quote(filename, safe="/\\")

def unescape_filename(filename):
    return urllib.unquote(filename)

class FileBackedObject(FileLikeObject):
    """ A FileBackedObject is a stream which reads and writes physical
    files on disk.

    The file:// URL scheme is used.
    """
    def __init__(self, uri, mode):
        filename = uri
        if not uri.startswith("file://"):
            filename = oracle.resolve(uri, AFF4_STORED)

        if not filename.startswith("file://"):
            Raise("You must have a fully qualified urn here, not %s" % filename)

        filename = filename[len("file://"):]
        escaped = escape_filename(filename)
        if mode == 'r':
            self.fd = open(escaped, 'rb')
            self.fd.seek(0,2)
            self.size = self.fd.tell()
            self.fd.seek(0)
        else:
            try:
                os.makedirs(os.path.dirname(escaped))
            except Exception,e:
                pass

            try:
                self.fd = open(escaped, 'r+b')
            except:
                self.fd = open(escaped, 'w+b')
                
        AFFObject.__init__(self, uri, mode)

    def seek(self, offset, whence=0):
        self.fd.seek(offset, whence)

    def tell(self):
        return self.fd.tell()

    def read(self, length=None):
        if length is None:
            return self.fd.read()
        
        result = self.fd.read(length)
        return result

    def write(self, data):
        self.fd.write(data)
        return len(data)

    def close(self):
        self.fd.close()

    def flush(self):
        self.fd.flush()


try:
    import pycurl

## TODO implement caching here
    class HTTPObject(FileLikeObject):
        """ This class handles http URLs.

        We support both download and upload (read and write) through
        libcurl. Uploading is done via webdav so your web server must
        be configured to support webdav.

        This implementation uses webdav to write the image on the server as
        needed. You can use a Zip volume or a directory volume as needed. The
        following is an example of how to set up apache to support
        webdav. Basically add this to the default host configuration file:

        <Directory "/var/www/webdav/" >
             DAV On
             AuthType Basic
             AuthName "test"
             AuthUserFile /etc/apache2/passwd.dav

             <Limit PUT POST DELETE PROPPATCH MKCOL COPY BCOPY MOVE LOCK \
             UNLOCK>
                Allow from 127.0.0.0/255.0.0.0
                Require user mic
                Satisfy Any
             </Limit>
        </Directory>

        This allows all access from 127.0.0.1 but requires an authenticated
        user to modify things from anywhere else. Read only access is allowed
        from anywhere.
        """
        handle = None
        
        def __init__(self, urn=None, mode='r'):
            FileLikeObject.__init__(self, urn, mode)
            if urn:
                if mode=='r':
                    self.handle = pycurl.Curl()
                    self.buffer = StringIO.StringIO()

                    def parse_header_callback(header):
                        ## we are looking for a Content-Range header
                        if header.lower().startswith("content-range: bytes"):
                            header_re = re.compile(r"(\d+)-(\d+)/(\d+)")
                            m = header_re.search(header)
                            if m:
                                self.size = long(m.group(3))

                    self.handle.setopt(pycurl.VERBOSE, 0)
                    self.handle.setopt(pycurl.URL, urn)
                    self.handle.setopt(pycurl.FAILONERROR, 1)
                    self.handle.setopt(pycurl.WRITEFUNCTION, self.buffer.write)
                    self.handle.setopt(pycurl.HEADERFUNCTION, parse_header_callback)

                    ## Make a single fetch from the url to work out our size:
                    self.read(1)
                    self.seek(0)
                    
                elif mode=='w':
                    self.handle = pycurl.Curl()
                    self.multi_handle = pycurl.CurlMulti()
                    self.send_buffer = ''

                    def read_callback(length):
                        result = self.send_buffer[:length]
                        self.send_buffer = self.send_buffer[length:]

                        return result

                    self.handle.setopt(pycurl.VERBOSE, 0)
                    self.handle.setopt(pycurl.URL, self.urn)
                    self.handle.setopt(pycurl.FAILONERROR, 1)
                    self.handle.setopt(pycurl.WRITEFUNCTION, lambda x: len(x))
                    self.handle.setopt(pycurl.INFILESIZE_LARGE, 0xFFFFFFFFL)
                    self.handle.setopt(pycurl.UPLOAD, 1)
                    self.handle.setopt(pycurl.READFUNCTION, read_callback)

                    self.multi_handle.add_handle(self.handle)
                
        def read(self, length=None):
            self.buffer.truncate(0)
            if length is None:
                length = self.size - self.readptr
                
            self.handle.setopt(pycurl.RANGE, "%d-%d" % (self.readptr, self.readptr + length))
            try:
                self.handle.perform()
            except pycurl.error,e:
                raise IOError("pycurl.error: %s" % e)

            result = self.buffer.getvalue()[:length]
            self.readptr += len(result)

            return result

        def flush(self):
            pass

        def write(self, data):
            if len(data)==0: return
            
            if self.mode!='w':
                Raise("Trying to write on an object opened for reading")
            
            self.send_buffer += data
            while 1:
                res, handle_count = self.multi_handle.perform()
                
                if handle_count==0:
                    time.sleep(1)

                if not self.send_buffer:
                    break

            self.readptr += len(data)
            self.size = max(self.size, self.readptr)
                
except ImportError:
    class HTTPObject(FileLikeObject):
        def __init__(self, urn=None, mode='r'):
            raise RuntimeError("HTTP streams are not implemented. You need to install libcurl python bindings (python-pycurl)")


class Store:
    """ This is a cache which expires objects in oldest first manner. """
    def __init__(self, limit=50, kill_cb=None):
        self.age = []
        self.hash = {}
        self.limit = limit
        self.kill_cb = kill_cb

    def expire(self):
        while len(self.age) > self.limit:
            x = self.age.pop(0)
            ## Kill the object if needed
            if self.kill_cb:
                self.kill_cb(self.hash[x])
                
            del self.hash[x]

    def add(self, urn, obj):
        self.hash[urn] = obj
        self.age.append(urn)
        self.expire()

    def get(self, urn):
        return self.hash[urn]

    def __contains__(self, obj):
        return obj in self.hash

    def __getitem__(self, urn):
        return self.hash[urn]

    def flush(self):
        if self.kill_cb:
            for x in self.hash.values():
                self.kill_cb(x)
                
        self.hash = {}
        self.age = []
    
class URNObject:
    """ A URNObject is an object in AFF4 space with a set of properties """
    def __init__(self, urn):
        self.properties = {}
        self.urn = urn
        self.read_lock = threading.Lock()
        self.write_lock = threading.Lock()

    def lock(self, mode='r'):
        if mode=='r':
            self.read_lock.acquire()
        else:
            self.write_lock.acquire()

    def release(self, mode='r'):
        if mode=='r':
            self.read_lock.release()
        else:
            self.write_lock.release()
        

    def __str__(self):
        result = ''
        verbosity = int(oracle.resolve(GLOBAL, CONFIG_VERBOSE))
        for attribute,v in self.properties.items():
            for value in v:
                if verbosity <= _INFO and attribute.startswith(VOLATILE_NS): continue
                
                result += "       %s = %s\n" % (attribute, value)

        return result
    
    def add(self, attribute, value):
        try:
            properties = self.properties[attribute]
        except KeyError:
            properties = []

        if value not in properties:
            properties.append(value)
        self.properties[attribute] = properties

    def delete(self, attribute):
        """ Remove all attributes of these name from the object """
        self.properties[attribute] = []

    def set(self, attribute, value):
        """ Set the attribute with this value remove all previous settings """
        self.properties[attribute] = [value, ]

    def __getitem__(self, attribute):
        try:
            return self.properties[attribute]
        except KeyError:
            return NoneObject("URN %s has no attribute %s" % (self.urn, attribute))

    def export(self, prefix=''):
        result =''
        for attribute, v in self.properties.items():
            if not attribute.startswith(VOLATILE_NS):
                for value in v:
                    result += prefix + "%s=%s\n" % (attribute, value)
                
        return result

    def flush(self, **kwargs):
        pass

class Resolver:
    """ The resolver is a central point for storing facts about the universe """
    def __init__(self):
        self.urn = {}
        self.read_cache = Store(50)
        self.write_cache = Store(50)
        self.clear_hooks()
        self.closed = {}
        self.urn_obj_class = URNObject

    def __getitem__(self, urn):
        try:
            obj = self.urn[urn]
        except KeyError:
            obj = self.urn_obj_class(urn)

        self.urn[urn] = obj
        return obj

    def set(self, uri, attribute, value):
        DEBUG(_DEBUG, "Setting %s: %s=%s", uri, attribute, value);
        ## A dict means we store an anonymous object:
        try:
            items = value.iteritems()
            pdb.set_trace()
            annon = "urn:annon:%s" % uuid4.uuid4()
            for k,v in items:
                self.set(annon, k ,v)

            value = anon
        except AttributeError: pass

        self[uri].set(attribute, value)
        
        ## Notify all interested parties
        for cb in self.set_hooks:
            cb(uri, attribute, value)
            
    def close(self, urn):
        DEBUG(_DEBUG, "Closing urn %s" % urn)
        #self.closed[urn] = self.urn[urn]
        del self.urn[urn]
        
    def add(self, uri, attribute, value):
        DEBUG(_DEBUG, "Adding %s: %s=%s", uri, attribute, value);
        self[uri].add(attribute, value)

        ## Notify all interested parties
        for cb in self.add_hooks:
            cb(uri, attribute, value)

    def delete(self, uri, attribute):
        self[uri].delete(attribute)

    def resolve(self, uri, attribute):
        for x in self.resolve_list(uri,attribute):
            return x

        return NoneObject("No attribute %s found on %s" % (attribute, uri))

    def resolve_list(self, uri, attribute):
        try:
            return self[uri][attribute]
        except KeyError:
            return NoneObject("Unable to resolve uri")

    def search_attribute(self, attribute):
        for urn in self.urn.keys():
            for value in self.resolve_list(urn, attribute):
                yield urn, value
        
    def create(self, class_reference):
        return class_reference(None, 'w')

    def cache_return(self, obj):
        DEBUG(_DEBUG, "Returning %s (%s)" % (obj.urn, obj.mode))
        try:
            if obj.mode == 'w':
                if obj.urn not in self.write_cache:
                    self.write_cache.add(obj.urn, obj)
            else:
                if obj.urn not in self.read_cache:
                    self.read_cache.add(obj.urn, obj)
        finally:
            ## Release the lock now
            self.release(obj.urn, obj.mode)
            DEBUG(_DEBUG,"Released %s", obj.urn)

    def open(self, uri, mode='r', interface=None):
        DEBUG(_DEBUG, "oracle: Openning %s (%s)" % (uri,mode))
        """ Opens the uri returning the requested object.

        If interface is specified we check that the object we return
        implements the correct interface or return an error.
        """
        result = None

        #if uri.startswith(FQN) and \
        #       not self.resolve(uri, AFF4_TYPE):
        #    pdb.set_trace()
        #    Raise("Trying to open a non existant or already closed object %s" % uri)

        ## If the uri is not complete here we guess its a file://
        if ":" not in uri:
            uri = "file://%s" % uri

        ## Check for links
        #if oracle.resolve(uri, AFF4_TYPE) == AFF4_LINK:
        #    uri = oracle.resolve(uri, AFF4_TARGET)

        try:
            if mode =='r':
                result = self.read_cache[uri]
            else:
                result = self.write_cache[uri]
        except KeyError:
            pass

        if not result:
            ## Do we know what type it is?
            type = self.resolve(uri, AFF4_TYPE)
            if type:
                for scheme, prefix, handler in DISPATCH:
                    if prefix == type:
                        result = handler(uri, mode)
                        result.mode = mode
                        break

        if not result:
            ## find the handler according to the scheme:
            for scheme, prefix, handler in DISPATCH:
                if scheme and uri.startswith(prefix):
                    result = handler(uri, mode)
                    result.mode = mode
                    break

        if result:
            self.lock(uri, mode)
            
            ## Try to seek it to the start
            try:
                result.seek(0)
            except: pass
            
            return result

        ## We dont know how to open it.
        return NoneObject("Dont know how to handle URN %s. (type %s)" % (uri, type))

    def lock(self, uri, mode='r'):
        ## Obtain a lock on the object
        try:
            obj = self[uri]
        except KeyError:
            obj = self[uri] = self.urn_obj_class(uri)

        DEBUG(_DEBUG, "Acquiring %s ",uri)
        obj.lock(mode)
        DEBUG(_DEBUG, "Acquired %s", uri)

    def release(self, uri, mode):
        ## Obtain a lock on the object
        try:
            obj = self[uri]
        except KeyError:
            obj = self[uri] = self.urn_obj_class(uri)

        DEBUG(_DEBUG, "Releasing %s ",uri)
        obj.lock.release(mode)

    def __str__(self):
        result = ''
        verbosity = int(oracle.resolve(GLOBAL, CONFIG_VERBOSE))
        keys = self.urn.keys()
        keys.sort()
        
        for urn in keys:
            if not urn: continue
            obj = self.urn[urn]
            if verbosity <= _DETAILED and urn.startswith(VOLATILE_NS): continue
            
            if verbosity - (_DETAILED - int(self.resolve(urn, AFF4_HIGHLIGHT))) < 0:
                continue
            
            attr_str = obj.__str__()
            if not attr_str: continue
            result += "\n****** %s \n%s" % (urn, attr_str)

        return result

    full_props_re = re.compile("([^ ]+) ([^=]+)=(.+)")
    relative_props_re = re.compile("([^=]+)=(.+)")

    def parse_properties(self, data, context=None):
        """ Parses the properties given in the data and add to the resolver.

        Context is used if no explicit subject is given.
        """
        for line in data.splitlines():
            ## Is it a fully qualified line?
            m = self.full_props_re.match(line)
            if m:
                self.add(m.group(1), m.group(2), m.group(3))
                continue
            ## Or relative to the current context?
            m = self.relative_props_re.match(line)
            if m:
                self.add(context, m.group(1), m.group(2))
                continue

            DEBUG(_WARNING,"Unknown line in properties: %s" % line)

    def export(self, subject, prefix=''):
        return self[subject].export(prefix=prefix)

    def export_all(self):
        result = ''
        for urn, obj in self.urn.items():
            result += obj.export(prefix=urn + " ")
        return result

    def register_add_hook(self, cb):
        """ Callbacks may be added here to be notified of add
        events. The callback will be called with the following
        prototype:

        cb(urn, attribute, value)
        """
        self.add_hooks.append(cb)

    def clear_hooks(self):
        self.add_hooks = []
        self.set_hooks = []
        
    def register_set_hook(self, cb):
        self.set_hooks.append(cb)

oracle = Resolver()

import zipfile

class ZipFileStream(FileLikeObject):
    """ This is a stream object which reads data from within a zip
    file. Note that the archive file is mapped and each read request
    is made from the backing fd, rather than reading and decompressing
    the whole thing at once - this makes it efficient to read very
    large bevies.
    """
    def __init__(self, urn=None, mode='r'):
        AFFObject.__init__(self, urn, mode)

        ## What volume are we in?
        self.volume = oracle.resolve(self.urn, AFF4_STORED)
        
        ## Where is it stored?
        self.backing_fd = oracle.resolve(self.volume, AFF4_STORED)

        ## our base offset
        self.base_offset = parse_int(oracle.resolve(self.urn, AFF4_VOLATILE_FILE_OFFSET))
        self.compression = parse_int(oracle.resolve(self.urn, AFF4_VOLATILE_COMPRESSION))
        self.compress_size = parse_int(oracle.resolve(self.urn, AFF4_VOLATILE_COMPRESSED_SIZE))
        self.size = parse_int(oracle.resolve(self.urn, AFF4_SIZE))

    def read(self, length=None):
        if length is None:
            length = self.size

        length = min(self.size - self.readptr, length)

        if self.compression == zipfile.ZIP_STORED:
            fd = oracle.open(self.backing_fd,'r')
            try:
                fd.seek(self.base_offset + self.readptr)
                result = fd.read(length)
            finally:
                oracle.cache_return(fd)
                
            self.readptr += len(result)

            return result
        elif self.compression == ZIP_DEFLATED:
            ## We assume that the compressed segment is small enough
            ## to do all this in memory. This is the case with AFF4
            ## which only uses compressed segments for small files,
            ## but may not the case for logical file images.
            data = self.get_data()
            result = data[self.readptr:self.readptr + length]
            self.readptr += len(result)

            return result

    def get_data(self):
        if not self.data:
            fd = oracle.open(self.backing_fd,'r')
            try:
                fd.seek(self.base_offset)
                cdata = fd.read(self.compress_size)
            finally:
                oracle.cache_return(fd)

            if self.compression == ZIP_DEFLATED:
                dc = zlib.decompressobj(-15)
                self.data = dc.decompress(cdata) + dc.flush()
            else:
                self.data = cdata
                
        return self.data

class ImageWorker(threading.Thread):
    """ This is a worker responsible for creating a full bevy """
    def __init__(self, urn, bevy_number,
                 chunk_size, chunks_in_segment, condition_variable=None,
                 compression=9):
        """ Set up a new worker.

        The condition variable will be notified when we finish.
        """
        threading.Thread.__init__(self)

        self.condition_variable = condition_variable
        self.buffer = StringIO.StringIO()
        self.bevy = StringIO.StringIO()
        self.bevy_index = StringIO.StringIO()
        self.chunk_size = chunk_size
        self.chunks_in_segment = chunks_in_segment
        self.bevy_size = chunk_size * chunks_in_segment
        self.len = 0
        self.urn = urn
        self.bevy_number = bevy_number
        self.compression = compression
        
    def write(self, data):
        available_to_read = min(self.bevy_size - self.buffer.len, len(data))
        self.buffer.write(data[:available_to_read])
        
        return data[available_to_read:]

    def run(self):
        """ This is run when we have a complete bevy """
        DEBUG(_DEBUG, "Starting thread")
        self.buffer.seek(0)
        offset = 0
        while self.buffer.tell() < self.buffer.len:
            data = self.buffer.read(self.chunk_size)
            if self.compression > 0:
                cdata = zlib.compress(smart_string(data),
                                      int(self.compression))
            else:
                cdata = data
                
            self.bevy.write(cdata)
            self.bevy_index.write(struct.pack("<L", offset))
            offset += len(cdata)

        self.bevy_index.write(struct.pack("<L", 0xFFFFFFFF))

        subject = fully_qualified_name("%08d" % self.bevy_number, self.urn)

        ## we calculate the SHA (before we grab the lock on the
        ## volume)
        hash_type = oracle.resolve(self.urn, AFF4_HASH_TYPE)
        if hash_type == AFF4_SHA:
            oracle.set(subject, AFF4_SHA,
                       hashlib.sha1(self.bevy.getvalue()).\
                       digest().encode("base64").strip())

        ## Grab the volume
        volume_urn = oracle.resolve(self.urn, AFF4_STORED)
        volume = oracle.open(volume_urn, 'w')
        try:
           ## Write the bevy
            if self.buffer.len > 0:
                filename = oracle.resolve(volume_urn, AFF4_STORED)
                DEBUG(_INFO, "%s: %s %s/%sMb (%d%%)" , filename,
                      subject,
                      (self.bevy.len / 1024 / 1024),
                      (self.bevy_size/ 1024 / 1024),
                      (100 * self.bevy.len) / self.buffer.len)
            volume.writestr(subject,
                            self.bevy.getvalue())
            volume.writestr(subject + '.idx',
                            self.bevy_index.getvalue())
        finally:
            ## Done
            oracle.cache_return(volume)

        ## Notify that we are finished
        self.condition_variable.acquire()
        self.condition_variable.notify()
        self.condition_variable.release()

        DEBUG(_DEBUG,"Finishing thread")
        
class Image(FileLikeObject):
    """ A Image stores a large, seekable, compressed, contiguous, block of data.

    We do this by splitting the data into chunks, each chunk is stored
    in a bevy. A bevy is a segment which holds a given number of
    chunks back to back. The offset of each chunk within the bevy is
    given by the index segment.
    """
    def __init__(self, urn=None, mode='r'):
        FileLikeObject.__init__(self, urn, mode)
        if urn:
            container = oracle.resolve(self.urn, AFF4_STORED)
            oracle.add(container, AFF4_CONTAINS, self.urn)

            self.chunk_size = parse_int(oracle.resolve(self.urn, AFF4_CHUNK_SIZE)) or 32*1024
            self.chunks_in_segment = parse_int(oracle.resolve(self.urn, AFF4_CHUNKS_IN_SEGMENT)) or 2048
            self.compression = read_with_default(self.urn, AFF4_COMPRESSION, 8)
            self.chunk_cache = Store()
            self.bevy_number = 0
            self.running = []
            self.condition_variable = threading.Condition()

            if mode=='w':
                self.writer = ImageWorker(self.urn, self.bevy_number,
                                          self.chunk_size, self.chunks_in_segment,
                                          compression = self.compression,
                                          condition_variable = self.condition_variable)

    def finish(self):
        oracle.set(self.urn, AFF4_TYPE, AFF4_IMAGE)
        oracle.set(self.urn, AFF4_INTERFACE, AFF4_STREAM)

        ## This marks the image as dirty
        oracle.set(self.urn, AFF4_VOLATILE_DIRTY, 1)
        self.__init__(self.urn, self.mode)

    def write(self, data):
        self.readptr += len(data)
        self.size = max(self.size, self.readptr)

        while 1:
            data = self.writer.write(data)

            ## All the data fit:
            if not data:
                return

            ## It didnt all fit - flush the worker, and get a new one here
            self.writer.start()
            self.running.append(self.writer)
            DEBUG(_DEBUG, "%s" % self.running)
            
            ## Update our view of the currently running threads
            while 1:
                number_of_threads = parse_int(oracle.resolve(GLOBAL, CONFIG_THREADS)) or 2
                self.running = [ x for x in self.running if x.is_alive() ]
                if len(self.running) >= number_of_threads:
                    self.condition_variable.acquire()
                    self.condition_variable.wait(10)
                    self.condition_variable.release()
                else: break
            
            self.bevy_number += 1
            self.writer = ImageWorker(self.urn, self.bevy_number,
                                      self.chunk_size, self.chunks_in_segment,
                                      compression = self.compression,
                                      condition_variable=self.condition_variable)

    def close(self):
        self.running.append(self.writer)
        self.writer.start()

        ## Wait untill all workers are finished
        for x in self.running:
            x.join()

        oracle.set(self.urn, AFF4_SIZE, self.size)

        AFFObject.close(self)

        ## Ok, we are done now
        oracle.delete(self.urn, AFF4_VOLATILE_DIRTY)

    def partial_read(self, length):
        """ Read as much as is possible at the current point without
        exceeding a chunk
        """
        chunk_id = self.readptr / self.chunk_size
        chuck_offset = self.readptr % self.chunk_size
        available_to_read = min(self.chunk_size - chuck_offset, length)

        try:
            chunk = self.chunk_cache[chunk_id]
        except KeyError:
            bevy = chunk_id / self.chunks_in_segment
            chunk_in_bevy = chunk_id % self.chunks_in_segment
            
            bevy_urn = "%s/%08d" % (self.urn, bevy)
            
            fd = oracle.open("%s.idx" % bevy_urn, 'r')
            try:
                data = fd.get_data()
                offset, offset_end = struct.unpack(
                    "<LL", data[4 * chunk_in_bevy:4 * chunk_in_bevy + 8])
                length = offset_end - offset
            finally:
                oracle.cache_return(fd)

            fd = oracle.open(bevy_urn, 'r')
            try:
                fd.seek(offset)
                if self.compression > 0:
                    chunk = zlib.decompress(fd.read(length))
                else:
                    chunk = fd.read(length)
            finally:
                oracle.cache_return(fd)
            
            self.chunk_cache.add(chunk_id, chunk)
            
        data = chunk[chuck_offset: chuck_offset + available_to_read]
        return data
        
    def read(self, length=None):        
        if length is None:
            length = self.size

        length = min(self.size - self.readptr, length)

        result = ''
        while length > 0:
            data = self.partial_read(length)
            if len(data)==0:
                break

            self.readptr += len(data)
            result += data
            length -= len(data)

        return result

class RAWVolume(AFFVolume):
    """ A Raw image.

    Raw volumes are basically dd images. We get all the AFF4_STORED
    properties, and do a filesystem glob to discover all parts of the
    image. These are then joined together in a map in sorted order.
    """
    type = AFF4_RAW_VOLUME
    
    def __init__(self, urn, mode='r'):
        if urn:
            self.urn = urn
            stored = oracle.resolve(urn, AFF4_STORED) or \
                     Raise("Can not find storage for Volumes %s" % urn)

            try:
                self.load_from(stored)
            except: pass

            ## Do we need to adjust the urn:
            if self.urn != urn:
                oracle.delete(urn, AFF4_STORED)
                oracle.set(self.urn, AFF4_STORED, stored)

            oracle.set(stored, AFF4_CONTAINS, self.urn)
            oracle.set(self.urn, AFF4_TYPE, self.type)
            oracle.set(self.urn, AFF4_INTERFACE, AFF4_VOLUME)
            ## We just created a new volume - set it to dirty to
            ## ensure it gets closed off propertly
            oracle.set(self.urn, AFF4_VOLATILE_DIRTY, "1")
        else:
            AFFObject.__init__(self, urn, mode)
                        
    def finish(self):
        self.__init__(self.urn, self.mode)

    def load_from(self, urn):
        fd = oracle.open(urn, 'r')
        try:
            basename = os.path.basename(fd.urn)
            new_urn = FQN + basename
            self.urn = new_urn
            oracle.set(new_urn, AFF4_STORED, fd.urn)
            oracle.set(new_urn, AFF4_TYPE, AFF4_RAW_STREAM)
            oracle.set(fd.urn, AFF4_CONTAINS, new_urn)
            oracle.set(fd.urn, AFF4_TYPE, AFF4_RAW_STREAM)
            oracle.set(new_urn, AFF4_CONTAINS, fd.urn)
            oracle.set(new_urn, AFF4_HIGHLIGHT, _DETAILED)
            oracle.set(new_urn, AFF4_SIZE, fd.size)
        finally:
            oracle.cache_return(fd)

class ZipVolume(RAWVolume):
    """ AFF4 Zip Volumes store segments within zip files """
    type = AFF4_ZIP_VOLUME

    def writestr(self, subject, data, compress_type = ZIP_STORED):
        """ Write the filename on the archive.

        subject is a fully qualified name or relative to the current volume.
        """
        filename = escape_filename(relative_name(subject, self.urn))

        ## Where are we stored?
        stored = oracle.resolve(self.urn, AFF4_STORED)

        ## This locks the backing_fd for exclusive access
        backing_fd = oracle.open(stored,'w')
        try:
            ## Mark the file as dirty
            oracle.set(self.urn, AFF4_VOLATILE_DIRTY, '1')
            time.sleep(0.01)

            ## Where should we write the new file?
            directory_offset = parse_int(oracle.resolve(self.urn, AFF4_DIRECTORY_OFFSET)) or 0

            zinfo = zipfile.ZipInfo(filename = filename,
                                    date_time=time.gmtime(time.time())[:6])

            zinfo.external_attr = 0600 << 16L      # Unix attributes        
            zinfo.header_offset = directory_offset
            zinfo.file_size = len(data)
            zinfo.CRC = 0xFFFFFFFF & zlib.crc32(data)

            ## Compress the data if needed
            zinfo.compress_type = compress_type
            if zinfo.compress_type == ZIP_DEFLATED:
                co = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION,
                     zlib.DEFLATED, -15)
                data = co.compress(data) + co.flush()
                zinfo.compress_size = len(data)    # Compressed size
            else:
                zinfo.compress_size = zinfo.file_size

            ## Write the header and data
            backing_fd.seek(directory_offset)
            backing_fd.write(zinfo.FileHeader())
            backing_fd.write(data)

            ## Add this new file to the resolver
            subject = fully_qualified_name(subject, self.urn)
            self.import_zinfo(subject, zinfo)

            ## Adjust the new directory_offset
            oracle.set(self.urn, AFF4_DIRECTORY_OFFSET, backing_fd.tell())
        finally:
            ## Done with the backing file now (this will unlock it too)
            oracle.cache_return(backing_fd)

    def write_CD(self, backing_fd):
        """ Write the central directory on backing_fd """
        ## Get all the files we own
        count = 0
        extra = []
        pos1 = parse_int(oracle.resolve(self.urn, AFF4_DIRECTORY_OFFSET))
        backing_fd.seek(pos1)

        for subject in oracle.resolve_list(self.urn, AFF4_CONTAINS):
            ## We only care about segments here
            if oracle.resolve(subject, AFF4_TYPE) != AFF4_SEGMENT: continue

            filename = escape_filename(relative_name(subject, self.urn))
            zinfo = zipfile.ZipInfo(filename)

            zinfo.header_offset = parse_int(oracle.resolve(subject, AFF4_VOLATILE_HEADER_OFFSET))
            zinfo.compress_size = parse_int(oracle.resolve(subject, AFF4_VOLATILE_COMPRESSED_SIZE))
            zinfo.file_size = parse_int(oracle.resolve(subject, AFF4_SIZE))
            zinfo.compress_type = parse_int(oracle.resolve(subject, AFF4_VOLATILE_COMPRESSION))
            zinfo.CRC = parse_int(oracle.resolve(subject, AFF4_VOLATILE_CRC))
            zinfo.date_time = parse_int(oracle.resolve(subject, AFF4_TIMESTAMP)) or \
                              int(time.time())

            count = count + 1
            dt = time.gmtime(zinfo.date_time)[:6]
            dosdate = (dt[0] - 1980) << 9 | dt[1] << 5 | dt[2]
            dostime = dt[3] << 11 | dt[4] << 5 | (dt[5] // 2)
            extra = []
            if zinfo.file_size > ZIP64_LIMIT \
                    or zinfo.compress_size > ZIP64_LIMIT:
                extra.append(zinfo.file_size)
                extra.append(zinfo.compress_size)
                file_size = 0xffffffff
                compress_size = 0xffffffff
            else:
                file_size = zinfo.file_size
                compress_size = zinfo.compress_size

            if zinfo.header_offset > ZIP64_LIMIT:
                extra.append(zinfo.header_offset)
                header_offset = 0xffffffffL
            else:
                header_offset = zinfo.header_offset

            extra_data = zinfo.extra
            if extra:
                # Append a ZIP64 field to the extra's
                extra_data = struct.pack(
                        '<HH' + 'Q'*len(extra),
                        1, 8*len(extra), *extra) + extra_data

                extract_version = max(45, zinfo.extract_version)
                create_version = max(45, zinfo.create_version)
            else:
                extract_version = zinfo.extract_version
                create_version = zinfo.create_version

            try:
                filename, flag_bits = zinfo.filename, zinfo.flag_bits
                centdir = struct.pack(structCentralDir,
                 stringCentralDir, create_version,
                 zinfo.create_system, extract_version, zinfo.reserved,
                 flag_bits, zinfo.compress_type, dostime, dosdate,
                 zinfo.CRC, compress_size, file_size,
                 len(filename), len(extra_data), len(zinfo.comment),
                 0, zinfo.internal_attr, zinfo.external_attr,
                 header_offset)
            except DeprecationWarning:
                print >>sys.stderr, (structCentralDir,
                 stringCentralDir, create_version,
                 zinfo.create_system, extract_version, zinfo.reserved,
                 zinfo.flag_bits, zinfo.compress_type, dostime, dosdate,
                 zinfo.CRC, compress_size, file_size,
                 len(zinfo.filename), len(extra_data), len(zinfo.comment),
                 0, zinfo.internal_attr, zinfo.external_attr,
                 header_offset)
                raise
            backing_fd.write(centdir)
            backing_fd.write(filename)
            backing_fd.write(extra_data)
            backing_fd.write(zinfo.comment)

        pos2 = backing_fd.tell()
        # Write end-of-zip-archive record
        centDirCount = count
        centDirSize = pos2 - pos1
        centDirOffset = pos1
        if (centDirCount >= ZIP_FILECOUNT_LIMIT or
            centDirOffset > ZIP64_LIMIT or
            centDirSize > ZIP64_LIMIT):
            # Need to write the ZIP64 end-of-archive records
            zip64endrec = struct.pack(
                    structEndArchive64, stringEndArchive64,
                    44, 45, 45, 0, 0, centDirCount, centDirCount,
                    centDirSize, centDirOffset)
            backing_fd.write(zip64endrec)

            zip64locrec = struct.pack(
                    structEndArchive64Locator,
                    stringEndArchive64Locator, 0, pos2, 1)
            backing_fd.write(zip64locrec)
            centDirCount = min(centDirCount, 0xFFFF)
            centDirSize = min(centDirSize, 0xFFFFFFFF)
            centDirOffset = min(centDirOffset, 0xFFFFFFFF)

        # check for valid comment length
        endrec = struct.pack(structEndArchive, stringEndArchive,
                             0, 0, centDirCount, centDirCount,
                             centDirSize, centDirOffset, len(self.urn))
        backing_fd.write(endrec)
        backing_fd.write(self.urn)
        backing_fd.flush()

    def close(self):
        """ Close and write a central directory structure on this zip file.
        
        This code was adapted from python2.6's zipfile.ZipFile.close()
        """
        ## Is this file dirty?
        if oracle.resolve(self.urn, AFF4_VOLATILE_DIRTY):
            result = oracle.export_volume(self.urn)
                                          
            ## Store volume properties
            self.writestr("properties", result,
                          compress_type = ZIP_DEFLATED)

            ## Where are we stored?
            stored = oracle.resolve(self.urn, AFF4_STORED)
            
            ## This locks the backing_fd for exclusive access
            backing_fd = oracle.open(stored,'w')
            try:
                self.write_CD(backing_fd)
            finally:
                oracle.cache_return(backing_fd)
            
            oracle.delete(self.urn, AFF4_VOLATILE_DIRTY)
            #oracle.close(self.urn)
            ## We allow the object to persist in the resolver after we
            ## closed it - could be useful if we need to read it now
            oracle.cache_return(self)
            
    def load_from(self, filename):
        """ Tries to open the filename as a ZipVolume """
        fileobj = oracle.open(filename, 'r')
        ## We parse out the CD of each file and build an index
        try:
            zf = zipfile.ZipFile(fileobj, mode='r', allowZip64=True)
        except:
            zf = zipfile.ZipFile(fileobj, mode='r')
        finally:
            oracle.cache_return(fileobj)
        
        self.zf = zf
        
        ## Here we should have a valid zip file - what is our URN?
        try:
            self.urn = zf.comment
            assert(self.urn.startswith(FQN))
        except Exception,e:
            ## Nope - maybe its in a __URN__ member
            try:
                self.urn = zf.read("__URN__")
                assert(self.urn.startswith(FQN))
            except:
                DEBUG(_WARNING, "Volume does not have a valid URN - using temporary URN %s" % self.urn)

        infolist = zf.infolist()
        for zinfo in infolist:
            subject = fully_qualified_name(unescape_filename(zinfo.filename), self.urn)

            if zinfo.filename.endswith("properties"):
                ## A properties file refers to the object which
                ## contains it:
                oracle.parse_properties(zf.read(zinfo.filename),
                                        context=os.path.dirname(subject))
                
            self.import_zinfo(subject, zinfo)

        oracle.set(self.urn, AFF4_STORED, filename)
        oracle.set(filename, AFF4_CONTAINS, self.urn)
        oracle.set(self.urn, AFF4_DIRECTORY_OFFSET, zf.start_dir)
            
    def import_zinfo(self, subject, zinfo):
        """ Import all the info from a zinfo into the resolver """
        ## Add some stats to the resolver these can be used in
        ## place of zinfo in future:
        oracle.add(self.urn, AFF4_CONTAINS, subject)
        oracle.set(subject, AFF4_STORED, self.urn)
        oracle.set(subject, AFF4_TYPE, AFF4_SEGMENT)
        oracle.set(subject, AFF4_INTERFACE, AFF4_STREAM)

        oracle.set(subject, AFF4_VOLATILE_HEADER_OFFSET, zinfo.header_offset)
        oracle.set(subject, AFF4_VOLATILE_CRC, zinfo.CRC)
        oracle.set(subject, AFF4_VOLATILE_COMPRESSED_SIZE, zinfo.compress_size)
        oracle.set(subject, AFF4_SIZE, zinfo.file_size)
        oracle.set(subject, AFF4_VOLATILE_COMPRESSION, zinfo.compress_type)
        oracle.set(subject, AFF4_TIMESTAMP, int(time.mktime(zinfo.date_time +\
                                            (0,) * (9-len(zinfo.date_time)))))

        ## We just store the actual offset where the file is
        ## so we dont need to keep calculating it all the time
        oracle.set(subject, AFF4_VOLATILE_FILE_OFFSET, zinfo.header_offset +
                   sizeFileHeader + len(zinfo.filename))

## Implement an EWF AFF4 Volume
try:
    import ewf

    class EWFVolume(ZipVolume):
        """ An AFF4 class to handle EWF volumes.

        Based on the pyflag python bindings.
        """
        type = AFF4_EWF_VOLUME

        def load_from(self, urn):
            """ Load volume from the URN """
            if urn.startswith(FQN):
                Raise("EWF module only supports storage to real files")

            if urn.startswith("file://"):
                filename = urn[7:]
            else:
                filename = urn
                
            ## Try to glob the volumes
            base, ext = os.path.splitext(filename)
            if not ext.lower().startswith(".e"):
                Raise("EWF files usually have an extension of .E00")

            files = glob.glob(base + ".[Ee]*")
            self.handler = ewf.ewf_open(files)
            ## Now add headers
            h = self.handler.get_headers()
            h['md5'] = h.get('md5','').encode("hex")

            ## Try to make a unique volume URN
            try:
                self.urn = h["md5"]
            except: self.urn = base
            self.urn = FQN + self.urn
            
            oracle.set(self.urn, AFF4_TYPE, AFF4_EWF_VOLUME)
            oracle.set(self.urn, AFF4_INTERFACE, AFF4_VOLUME)
            oracle.set(self.urn, AFF4_STORED, urn)
            
            ## The stream URN is based on the volume
            stream_urn = self.urn + "/stream"
            oracle.set(self.urn, AFF4_CONTAINS, stream_urn)
            oracle.set(stream_urn, AFF4_STORED, self.urn)
            oracle.set(stream_urn, AFF4_SIZE, self.handler.size)
            oracle.set(stream_urn, AFF4_TYPE, AFF4_EWF_STREAM)
            oracle.set(stream_urn, AFF4_INTERFACE, AFF4_STREAM)
            oracle.set(stream_urn, AFF4_HIGHLIGHT, _DETAILED)
            
            for k in h:
                oracle.set(self.urn, NAMESPACE + "ewf:" + k, h[k])

    VOLUME_DISPATCH.append(EWFVolume)

except ImportError:
    class EWFVolume(ZipVolume):
        def __init__(self, urn=None, mode='r'):
            raise RuntimeError("EWF streams are not implemented. You need to install libewf first")
    class EWFStream(EWFVolume):
        pass

class EWFStream(FileLikeObject):
    def read(self, length):
        volume_urn = oracle.resolve(self.urn, AFF4_STORED)
        volume = oracle.open(volume_urn, 'r')
        try:
            available_to_read = min(self.size - self.readptr, length)
            volume.handler.seek(self.readptr)

            data = volume.handler.read(available_to_read)
            self.readptr += len(data)
            return data
        finally:
            oracle.cache_return(volume)

## Implement an AFF1 backward compatible AFF4 Volume
try:
    import pyaff

    class AFF1Volume(ZipVolume):
        """ An AFF4 class to handle EWF volumes.

        Based on the pyflag python bindings.
        """
        type = AFF4_AFF1_VOLUME

        def load_from(self, urn):
            """ Load volume from the URN """
            if urn.startswith(FQN):
                Raise("EWF module only supports storage to real files")

            self.handler = pyaff.aff_open(urn)
            
            ## Now add headers
            h = self.handler.get_headers()

            ## Try to make a unique volume URN
            try:
                self.urn = h["image_gid"].encode("hex")
            except: self.urn = base
            self.urn = FQN + self.urn
            
            oracle.set(self.urn, AFF4_TYPE, AFF4_AFF1_VOLUME)
            oracle.set(self.urn, AFF4_INTERFACE, AFF4_VOLUME)
            oracle.set(self.urn, AFF4_STORED, urn)
            
            ## The stream URN is based on the volume
            stream_urn = self.urn + "/stream"
            oracle.set(self.urn, AFF4_CONTAINS, stream_urn)
            oracle.set(stream_urn, AFF4_STORED, self.urn)
            oracle.set(stream_urn, AFF4_SIZE, self.handler.size)
            oracle.set(stream_urn, AFF4_TYPE, AFF4_AFF1_STREAM)
            oracle.set(stream_urn, AFF4_INTERFACE, AFF4_STREAM)
            oracle.set(stream_urn, AFF4_HIGHLIGHT, _DETAILED)
            
            for k in h:
                oracle.set(self.urn, "aff1:" + k, h[k])

    class AFF1Stream(EWFStream):
        pass
    
    VOLUME_DISPATCH.append(AFF1Volume)    
except ImportError:
    class AFF1Stream(ZipVolume):
        def __init__(self, urn=None, mode='r'):
            raise RuntimeError("AFF1 legacy volumes are not implemented. You need to install afflib first")

    class AFF1Volume(AFF1Stream):
        pass

VOLUME_DISPATCH.extend([ZipVolume, RAWVolume])

class DirectoryVolume(AFFVolume):
    """ A directory volume is simply a way of storing all segments
    within a directory on disk.
    """

class Link(AFFObject):
    """ An AFF4 object which links to another object.

    When we open the link name, we return the AFF4_TARGET attribute.
    """            
    def finish(self):
        ## Make sure we write our properties file
        stored = oracle.resolve(self.urn, AFF4_STORED) or \
                      Raise("Link objects must be stored on a volume")
        oracle.add(stored, AFF4_CONTAINS, self.urn)
        oracle.set(self.urn, AFF4_TYPE, AFF4_LINK)
        self.target = oracle.resolve(self.urn, AFF4_TARGET) or \
                      Raise("Link objects must have a target attribute")
        self.size = parse_int(oracle.resolve(self.target, AFF4_SIZE)) or 0
        oracle.set(self.urn, AFF4_SIZE, self.size)
        
        return AFFObject.finish(self)

#     def close(self):
#         ## Make sure we write our properties file
#         stored = oracle.resolve(self.urn, AFF4_STORED)
#         volume = oracle.open(stored, 'w')
#         try:
#             volume.writestr(fully_qualified_name("properties", self.urn),
#                             oracle.export(self.urn),
#                             compress_type = ZIP_DEFLATED)
#         finally:
#             oracle.cache_return(volume)

class Map(FileLikeObject):
    """ A Map is an object which presents a transformed view of another
    stream.
    """
    def finish(self):
        oracle.set(self.urn, AFF4_TYPE, AFF4_MAP)
        oracle.set(self.urn, AFF4_INTERFACE, AFF4_STREAM)
        oracle.set(self.urn, AFF4_VOLATILE_DIRTY, 1)
        oracle.set(self.urn, AFF4_SIZE, 0)
        
        self.__init__(self.urn, self.mode)

    def __init__(self, uri=None, mode='r'):
        ## As a matter of convension we refer to our own offsets as
        ## image offsets and the offsets in the target as target
        ## offsets:

        ## This is a sorted array of image offsets for which we have
        ## mapping points:
        self.image_offsets = [0]
        self.last_image_offset_index = None

        ## There are the target offsets for each image_offset kept in
        ## self.image_offsets:
        self.target_offsets = {0:0}

        ## These are the targets for each image_offset in
        ## self.image_offsets:
        self.target_urns = {0:"@"}

        if uri:
            stored = oracle.resolve(uri, AFF4_STORED) or \
                          Raise("Map objects must be stored somewhere")

            oracle.add(stored, AFF4_CONTAINS, uri)
            
            ## This is not essential
            self.target = oracle.resolve(uri, AFF4_TARGET)# or \
            #Raise("Map objects must have a %s attribute" % AFF4_TARGET)

            self.blocksize = parse_int(oracle.resolve(uri, AFF4_BLOCKSIZE)) or 1
            self.size = parse_int(oracle.resolve(uri, AFF4_SIZE))

        ## Parse the map now:
        if uri and mode=='r':
            target_urn = oracle.resolve(uri, AFF4_TARGET)
            line_re = re.compile("(\d+),(\d+),(.+)")

            ## map data can be stored as an attribute or in its own segment
            map_data = oracle.resolve(uri, AFF4_MAP_DATA)
            if map_data:
                map_data = map_data.decode("string_escape")
            else:
                fd = oracle.open("%s/map" % uri)
                try:
                    fd.seek(0)
                    map_data= fd.get_data()
                finally:
                    oracle.cache_return(fd)
                
            for line in map_data.splitlines():
                m = line_re.match(line)
                if not m:
                    DEBUG(_WARNING, "Unable to parse map line '%s'" % line)
                else:
                    if m.group(3) == "@":
                        t = target_urn
                    else:
                        t = m.group(3)

                    ## Add the point to the map
                    self.add(parse_int(m.group(1)),
                             parse_int(m.group(2)),
                             t)

        FileLikeObject.__init__(self, uri, mode)

    def get_range(self):
        """ Calculates the range which encapsulates the current readptr

        Returns a triple -
        (map offset at start of range, target offset at start of range, length, target_urn) 
        """
        ## Terminology:
        ##  ^ target offset
        ##  |        X
        ##  |      /   <----- Mapping function
        ##  |    x
        ##  |----p---X-----n------ -> Image coords

        ## X - readptr
        ## p - previous point - image_offset_at_point
        ## x - target offset at previous point - target_offset_at_point
        ## n - next point available_to_read = n - X

        ## We try to find the previous point before the current readptr
        l = bisect.bisect_right(self.image_offsets, self.readptr) - 1
        image_offset_at_point = self.image_offsets[l]
        target_offset_at_point = self.target_offsets[image_offset_at_point]
        
        try:
            available_to_read = self.image_offsets[l+1] - \
                                self.readptr
        except IndexError:
            available_to_read = self.size - self.readptr

        target_urn = self.target_urns[image_offset_at_point]
        
        return image_offset_at_point, target_offset_at_point, available_to_read, target_urn
                    
    def partial_read(self, length):
        """ Read from the current offset as much as possible - may
        return less than whats needed."""

        (image_offset_at_point,
         target_offset_at_point,
         available_to_read,
         target_urn) =  self.get_range()

        available_to_read = min(available_to_read, length)
        
        target_offset = target_offset_at_point + \
                        self.readptr - image_offset_at_point
        
        ## Now do the read:
        target = oracle.open(target_urn, 'r')
        try:
            target.seek(target_offset)
            data = target.read(min(available_to_read, length))
        finally:
            oracle.cache_return(target)

        self.readptr += len(data)
        return data

    def read(self, length):
        length = min(length, self.size - self.readptr)
        result = ''
        while len(result) < length:
            data = self.partial_read(length - len(result))
            if not data: break
            result += data

        return result

    def write(self, data):
        target = oracle.resolve(self.urn, AFF4_TARGET) or \
                 Raise("Map objects must have a default target when using write()")
        backing_fd = oracle.open(target, 'w')
        try:
            ## we always append to our backing image
            backing_fd.seek(0,2)
            image_offset = backing_fd.tell()
            
            ## The first point on the new line
            left = self.add(self.readptr, image_offset, target) + 1
            backing_fd.write(data)
            self.readptr += len(data)

            ## The end point on the new line
            right = self.add(self.readptr, 0, AFF4_SPECIAL_URN_NULL)

            ## Now delete points from map between left and right -
            ## this overwrites previous map points:
            if left != right:
                tmp = self.image_offsets[left:right]
                self.image_offsets = self.image_offsets[:left] + \
                                     self.image_offsets[right:]

                for x in tmp:
                    del self.target_offsets[x]
                    del self.target_urns[x]
                    
            self.size = max(self.size, self.readptr)
        finally:
            oracle.cache_return(backing_fd)

    def readline(self, size=1024):
        offset = self.readptr
        result = self.read(size)
        try:
            result = result[:result.index("\n")]
            offset += len(result)+1
        except ValueError:
            offset += len(result)

        self.seek(offset)
        
        return result

    def write_from(self, target_urn, target_offset, target_length):
        """ Adds the next chunk from this target_urn. This advances
        the readptr.
        """
        self.add(self.readptr, target_offset, target_urn)
        self.readptr += target_length
        self.size = max(self.size, self.readptr)
        
    def add(self, image_offset, target_offset, target_urn):
        ## FIXME: This should be made more efficient by testing the
        ## array index of the previous write rather than searching it
        ## each time.
        l = bisect.bisect_left(self.image_offsets, image_offset)
        try:
            image_offset_at_point = self.image_offsets[l]
        except IndexError:
            self.image_offsets.append(image_offset)
            image_offset_at_point = image_offset
            
        ## A new point is added
        if image_offset_at_point != image_offset:
            self.image_offsets.insert(l, image_offset)

        self.target_offsets[image_offset] = target_offset
        self.target_urns[image_offset] = target_urn
        
        return l

    def close(self):
        if self.mode == 'r': return

        fd = StringIO.StringIO()
        oracle.set(self.urn, AFF4_SIZE, self.size)

        previous = None
        for x in self.image_offsets:
            ## Collapse points which are redundant
            if previous is not None and \
                   self.target_urns[previous]==self.target_urns[x]:
                prediction = x - previous + self.target_offsets[previous]
                if prediction == self.target_offsets[x]:
                    continue

            ## Try to compress the targets if possible (@ refers to
            ## the target attribute)
            target = self.target_urns[x]
            if target == self.target: target = "@"

            fd.write("%d,%d,%s\n" % (x, self.target_offsets[x],
                                     target))
            previous = x

        ## If its very small we can just store it as an attribute
        if fd.tell() < 1000:
            oracle.set(self.urn, AFF4_MAP_DATA, str(fd.getvalue()).encode("string_escape"))
        else:
            stored = oracle.resolve(self.urn, AFF4_STORED)
            volume = oracle.open(stored, 'w')
            try:
                volume.writestr(fully_qualified_name("map", self.urn),
                                fd.getvalue(), compress_type = ZIP_DEFLATED)
            finally:
                oracle.cache_return(volume)

        FileLikeObject.close(self)

        ## Ok, we are done now
        oracle.delete(self.urn, AFF4_VOLATILE_DIRTY)

    def explain(self):
        result = "Stream %s %s:\n   %s" % (
            self.__class__.__name__,
            self.urn,
            "\n   ".join(oracle.export(self.urn).splitlines()))

        result += "\n\n* "

        targets = set()
        targets.add(oracle.resolve(self.urn, AFF4_STORED))
        targets.add(oracle.resolve(self.urn, AFF4_TARGET))

        map = oracle.resolve(self.urn, AFF4_MAP_DATA)
        if not map:
            fd = oracle.open("%s/map" % self.urn, 'r')
            try:
                map = fd.get_data()
            finally:
                oracle.cache_return(fd)                

        for urn in self.target_urns.values():
            targets.add(urn)
                
        result += "Map %s:\n" % self.urn + map + "\n"

        result += "Targets:\n"
        for target in targets:
            if not target: continue
            ## Now explain the stored URN
            fd = oracle.open(target, 'r')
            try:
                result += "\n ".join(fd.explain().splitlines())
            finally:
                oracle.cache_return(fd)

        return result


try:
    from M2Crypto import Rand, X509, EVP, m2, RSA
    import M2Crypto

    class Identity(AFFObject):
        """ An Identity is an object which represents an X509 certificate"""
        x509 = None
        pkey = None

        ## These are properties that will be signed
        signable = set([AFF4_SIZE, AFF4_SHA])

        def __init__(self, urn=None, mode='r'):
            self.resolver = Resolver()
            
            if urn and not self.x509:
                ## Check to ensure that the oracle doesnt already have
                ## this Identity (there can only be one identity with this
                ## fingerprint active at once).
                if oracle.resolve(self.urn, AFF4_TYPE):
                    Raise("Identity %s already exists" % self.urn)

                ## Load the cert from the identity object
                fd = oracle.open(urn + "/cert.pem", 'r')
                try:
                    self.x509 = X509.load_cert_string(fd.read())
                finally:
                    oracle.cache_return(fd)
                
            AFFObject.__init__(self, urn, mode)

        def load_certificate(self, certificate_urn):
            fd = oracle.open(certificate_urn, 'r')
            try:
                certificate = fd.read()
                self.x509 = X509.load_cert_string(certificate)
            finally:
                oracle.cache_return(fd)

        def load_priv_key(self, key_urn):
            fd = oracle.open(key_urn, 'r')
            try:
                self.pkey = EVP.load_key_string(fd.read())
            finally:
                oracle.cache_return(fd)

        def finish(self):
            if not self.x509: return

            ## We set our urn from the certificate fingerprint
            self.urn = "%s/%s" % (AFF4_IDENTITY_PREFIX, self.x509.get_fingerprint())
            oracle.set(self.urn, AFF4_TYPE, AFF4_IDENTITY)

            ## Register an add hook with the oracle
            def add_cb(uri, attribute, value):
                if attribute in self.signable:
                    self.resolver.add(uri, attribute, value)

            def set_cb(uri, attribute, value):
                if attribute in self.signable:
                    self.resolver.set(uri, attribute, value)

            if self.x509 and self.pkey:
                ## Check that the private and public keys go together:
                if not self.x509.verify(self.pkey):
                    Raise("Public and private keys provided do not go with each other")

                oracle.register_add_hook(add_cb)
                oracle.register_set_hook(set_cb)

            AFFObject.finish(self)

        def verify(self, verify_cb = None):
            """ Loads all statements and verifies the hashes are correct """
            if not self.x509: Raise("No public key for identity %s" % self.urn)

            public_key = self.x509.get_pubkey()
            
            def cb(urn, attribute, value):
                ## This callback will be called whenever the parser
                ## reads a new property.
                if attribute == AFF4_SHA:
                    fd = oracle.open(urn, 'r')
                    digest = hashlib.sha1()
                    try:
                        while 1:
                            data = fd.read(1024 * 1024)
                            if not data: break
                            digest.update(data)

                        calculated = digest.digest()
                        value = value.decode("base64")
                    finally:
                        oracle.cache_return(fd)

                    verify_cb(urn, attribute, value, calculated)
                        
            self.resolver.register_add_hook(cb)
            
            for statement_urn in oracle.resolve_list(self.urn, AFF4_STATEMENT):
                ## Read and verify the statement
                statement = oracle.open(statement_urn, 'r')
                try:
                    statement_data = statement.read()
                finally: oracle.cache_return(statement)
                signature = oracle.open(statement_urn + ".sig", 'r')
                try:
                    sig_data = signature.read()
                finally: oracle.cache_return(signature)
                
                ## Now check the statement signature is correct:
                public_key.verify_init()
                public_key.verify_update(statement_data)
                if not public_key.verify_final(sig_data):
                    DEBUG(_WARNING, "Statement %s signature does not match!!! Skipping" % statement_urn)
                else:
                    self.resolver.parse_properties(statement_data)

        def load_encryption_keys(self):
            """ Search through all the encryption keys and load them.

            Note that keys are normally stored inside volumes, so this
            function should be called for each identity when a volume
            is loaded.
            """
            for encrypted_urn in oracle.resolve_list(self.urn, AFF4_CRYPTO_RSA):
                if not oracle.resolve(encrypted_urn, AFF4_VOLATILE_KEY):
                    if not self.pkey:
                        DEBUG(_WARNING, "Unable to load encryption keys since "
                              "private key is missing - do you need to specify it?")
                        Raise("Private key missing")
                    
                    ## Key is not present - we need to derive it
                    print "Will load key for %s" % encrypted_urn
                    fd = oracle.open("%s/%s" % (self.urn,encrypted_urn),'r')
                    try:
                        encrypted_key = fd.get_data()
                    finally: oracle.cache_return(fd)

                    key = m2.rsa_private_decrypt(
                        self.pkey.get_rsa().rsa, encrypted_key,
                        RSA.pkcs1_padding)

                    oracle.set(encrypted_urn, AFF4_VOLATILE_KEY, key)

        def save_encryption_keys(self):
            volume_urn = oracle.resolve(self.urn, AFF4_STORED) 
            volume = oracle.open(volume_urn, 'w')
            try:
                ## Encrypt all keys using the public key - this will
                ## allow the private key to unlock them
                for uri, key in oracle.search_attribute(AFF4_VOLATILE_KEY):
                    print "Exporting keys for %s" % uri
                    encrypted_key = m2.rsa_public_encrypt(
                        self.x509.get_pubkey().get_rsa().rsa, key, RSA.pkcs1_padding)
                    key_name = "%s/%s" % (self.urn, uri)
                    volume.writestr(key_name,
                                    encrypted_key)
                    oracle.set(self.urn, AFF4_CRYPTO_RSA, uri)
                    
                volume.writestr(fully_qualified_name("properties", self.urn),
                                oracle.export(self.urn),
                                compress_type = ZIP_DEFLATED)

                ## Ensure that the volume knows it has an identity
                oracle.set(volume_urn, AFF4_IDENTITY_STORED, self.urn)
            finally:
                oracle.cache_return(volume)

        def close(self):
            if not self.pkey: return
            
            volume_urn = oracle.resolve(self.urn, AFF4_STORED) 
            volume = oracle.open(volume_urn, 'w')
            try:
                statement = self.resolver.export_all()

                ## Sign the statement
                if self.pkey:
                    self.pkey.sign_init()
                    self.pkey.sign_update(statement)
                    signature = self.pkey.sign_final()

                statement_urn = fully_qualified_name(str(uuid.uuid4()),
                                                     self.urn)
                oracle.add(self.urn, AFF4_STATEMENT, statement_urn)

                volume.writestr(statement_urn, statement)
                volume.writestr(statement_urn + ".sig", signature)
                volume.writestr(fully_qualified_name("properties", self.urn),
                                oracle.export(self.urn),
                                compress_type = ZIP_DEFLATED)

                ## Make sure to store the certificate in the volume
                cert_urn = fully_qualified_name("cert.pem", self.urn)
                try:
                    cert = oracle.open(cert_urn, 'r')
                    oracle.cache_return(cert)
                except RuntimeError:
                    text = self.x509.as_text() + self.x509.as_pem()
                    volume.writestr(cert_urn, text)

                ## Ensure that the volume knows it has an identity
                oracle.set(volume_urn, AFF4_IDENTITY_STORED, self.urn)
            finally:
                oracle.cache_return(volume)


    class Encrypted(FileLikeObject):
        """ Encrypted streams provide a cryptographic transformation
        to their backing stream.

        Encrypted streams do not provide any storage of their own,
        they simply provide a transparent read/write crypto transform
        to another stream (usually an Image stream).
        """
        def prepare_passphrase(self, key_size):
            """ Pulls the passphrase from the resolver and calculates
            an intermediate key of the required size. The intermediate
            key is used to decrypt the AFF4_CRYPTO_PASSPHRASE_KEY
            attribute to produce the image key. This allows the image
            key to be encrypted using a number of different ways, and
            even have the passphrase changed without affecting the
            image key.

            This key is derived accroding to rfc2898.
            """
            round_count = parse_int(oracle.resolve(self.urn,
                                                   AFF4_CRYPTO_FORTIFICATION_COUNT))
            if not round_count:
                if self.mode == 'r':
                    Raise("Object not encrypted using passphrase")
                else:
                    round_count = struct.unpack("L", Rand.rand_bytes(
                        struct.calcsize("L")))[0] & 0xFFFF
                    
            self.iv = oracle.resolve(self.urn, AFF4_CRYPTO_IV).decode("base64") or \
                      Rand.rand_bytes(16)
            password = oracle.resolve(GLOBAL, AFF4_VOLATILE_PASSPHRASE) or \
                       M2Crypto.util.passphrase_callback(1)

            ## Update the crypto material
            if password:
                oracle.set(self.urn, AFF4_CRYPTO_FORTIFICATION_COUNT, round_count)
                oracle.set(self.urn, AFF4_CRYPTO_IV, b64_encode(self.iv))
                oracle.set(GLOBAL, AFF4_VOLATILE_PASSPHRASE, password)
                return EVP.pbkdf2(password, self.iv, round_count, key_size)

            #else: Raise("No password provided for encrypted stream")

        def encrypt_block(self, data, key, iv, mode=1):
            """ Returns data encrypted by the master image key and IV """
            c = M2Crypto.EVP.Cipher("aes_256_cbc", key, iv, mode)
            result = c.update(data)
            try:
                result += c.final()
            except: pass

            return result

        def decrypt_block(self, data, key, iv):
            return self.encrypt_block(data, key, iv, 0)
            
        def load_aes_key(self):
            """ Loads the aes key into this object, or generate a new one. """
            intermediate_key = self.prepare_passphrase(32)
            passphrase_key = oracle.resolve(self.urn, AFF4_CRYPTO_PASSPHRASE_KEY)
            if not passphrase_key:
                ## Make a new master key
                self.master_key = Rand.rand_bytes(32)
                if intermediate_key:
                    ## Use the intermediate_key to encrypt the master key
                    passphrase_key = self.encrypt_block(self.master_key,
                                                        intermediate_key, self.iv)
                
                    nonce = self.encrypt_block(self.iv, self.master_key, self.iv)

                    ## Store this in the resolver
                    oracle.set(self.urn, AFF4_CRYPTO_PASSPHRASE_KEY, b64_encode(passphrase_key))
                    oracle.set(self.urn, AFF4_CRYPTO_NONCE, b64_encode(nonce))
                
            else:
                ## we need to derive the master key from the passphrase_key
                intermediate_key = self.prepare_passphrase(32)
                passphrase_key = passphrase_key.decode("base64")
                
                self.master_key = self.decrypt_block(passphrase_key, intermediate_key, self.iv)
                
                nonce = oracle.resolve(self.urn, AFF4_CRYPTO_NONCE)
                if nonce:
                    ## check to make sure the key is actually right
                    nonce = nonce.decode("base64")
                    if self.encrypt_block(self.iv, self.master_key, self.iv)!=nonce:
                        DEBUG(_WARNING, "Passphrase incorrect")
                        Raise("Passphrase incorrect")
                    
            ## Since this is never written we dont need to encode it
            oracle.set(self.urn, AFF4_VOLATILE_KEY, self.master_key)

        def flush(self):
            oracle.set(self.urn, AFF4_SIZE, self.size)
            fd = oracle.open(self.target, 'w')
            fd.seek(0,2)
            try:
                if self.buffer:
                    ## pad the buffer a bit
                    self.buffer += '\x00' * 16
                    
                    block_number = fd.tell() / self.blocksize
                    iv = struct.pack("<QQ", block_number, block_number)

                    ## Flush the last bit of data:
                    cdata = self.encrypt_block(self.buffer, self.master_key, iv)
                    fd.write(cdata)
                    self.buffer = ''
            finally:
                oracle.cache_return(fd)

        def close(self):
            self.flush()

            ## Close the target stream as well
            fd = oracle.open(self.target, 'w')
            fd.close()

            ## Make sure we write our properties file
            stored = oracle.resolve(self.urn, AFF4_STORED)
            volume = oracle.open(stored, 'w')
            try:
                volume.writestr(fully_qualified_name("properties", self.urn),
                                oracle.export(self.urn),
                                compress_type = ZIP_DEFLATED)
            finally:
                oracle.cache_return(volume)

            oracle.close(self.urn)

        def __init__(self, urn=None, mode='r'):
            FileLikeObject.__init__(self, urn, mode)
            if urn:
                container = oracle.resolve(self.urn, AFF4_STORED) or \
                            Raise("Encrypted stream must be stored somewhere")
                oracle.add(container, AFF4_CONTAINS, self.urn)

                ## Try to get our master key
                self.master_key = oracle.resolve(urn, AFF4_VOLATILE_KEY)
                self.blocksize = parse_int(oracle.resolve(urn, AFF4_CRYPTO_BLOCKSIZE)) or \
                                 4 * 1024
                oracle.set(urn, AFF4_CRYPTO_BLOCKSIZE, self.blocksize)
                
                self.target = oracle.resolve(self.urn, AFF4_TARGET) or \
                              Raise("You must set a target for an encrypted stream")

                if not self.master_key:
                    self.load_aes_key()

                self.buffer = ''

        def write(self, data):
            self.buffer += data
            self.readptr += len(data)
            self.size = max(self.readptr, self.size)
            
            blocks = len(self.buffer) / self.blocksize
            if blocks > 0:
                fd = oracle.open(self.target, 'w')
                try:
                    fd.seek(0,2)
                    for i in range(blocks):
                        block_number = fd.tell() / self.blocksize
                        iv = struct.pack("<QQ", block_number, block_number)
                        
                        encrypted = self.encrypt_block(
                            self.buffer[i*self.blocksize:(i+1)*self.blocksize],
                            self.master_key,
                            iv)
                        ## Sometimes M2Crypto pads with an extra block
                        ## thats not needed (assuming blocksize is a
                        ## correct multiple of the AES blocksize.
                        data = encrypted[:self.blocksize]
                        fd.write(data)
                    self.buffer = self.buffer[(i+1) * self.blocksize:]
                    
                finally:
                    oracle.cache_return(fd)

        def partial_read(self, length):
            block_number, block_offset = divmod(self.readptr, self.blocksize)
            available_to_read = min(length , self.blocksize - block_offset)
            fd = oracle.open(self.target, 'r')
            try:
                fd.seek(block_number * self.blocksize)
                cdata = fd.read(self.blocksize) + 16 * 'a'
                iv = struct.pack("<QQ", block_number, block_number)

                decrypted = self.decrypt_block(
                    cdata, self.master_key,
                    iv)

                result = decrypted[block_offset:block_offset+available_to_read]
                
                self.readptr += len(result)
                return result
            finally:
                oracle.cache_return(fd)
                
        def read(self, length=None):
            if length is None: length = self.size

            ## Clamp the length to the size
            length = min(self.size-self.readptr, length)

            result = ''
            while len(result) < length:
                data = self.partial_read(length - len(result))
                if not data: break

                result += data

            return result
                    
        def finish(self):
            oracle.set(self.urn, AFF4_TYPE, AFF4_ENCRYTED)
            oracle.set(self.urn, AFF4_INTERFACE, AFF4_STREAM)
            oracle.set(self.urn, AFF4_VOLATILE_DIRTY, 1)
            self.__init__(self.urn, self.mode)

except ImportError:
    class Identity(AFFObject):
        def __init__(self, urn=None, mode='r'):
            Raise("Signing is not available without the M2Crypto module. Try 'apt-get install python-m2crypto'")

    class Encrypted(FileLikeObject):
        def __init__(self, urn=None, mode='r'):
            Raise("Encrypted streams are not available without the M2Crypto module. Try 'apt-get install python-m2crypto'")


class ErrorStream(FileLikeObject):
    """ ErrorStreams are special streams which either raise an
    exception or pad with 0's when read.

    This is used to raise an error condition when invalid data is read
    from an image. For example attempting to read bad blocks, or
    reading in sparse regions on an image.
    """
    def read(self, length):
        if oracle.resolve(self.urn, CONFIG_PAD):
            return '\x00' * length

        raise IOError("Invalid read of %s" % self.urn)
        
## This is a dispatch table for all handlers of a URL method. The
## format is scheme, URI prefix, handler class.
DISPATCH = [
    [ 1, "file://", FileBackedObject ],
    [ 1, "http://", HTTPObject ],
    [ 1, "https://", HTTPObject ],
    [ 0, AFF4_SEGMENT, ZipFileStream ],
    [ 0, AFF4_LINK, Link ],
    [ 0, AFF4_IMAGE, Image ],
    [ 0, AFF4_MAP, Map ],
    [ 0, AFF4_ENCRYTED, Encrypted ],
    [ 0, AFF4_IDENTITY, Identity],
    [ 0, AFF4_ZIP_VOLUME, ZipVolume ],
    [ 0, AFF4_ERROR_STREAM, ErrorStream],
    [ 0, AFF4_EWF_STREAM, EWFStream],
    [ 0, AFF4_EWF_VOLUME, EWFVolume],
    [ 0, AFF4_AFF1_STREAM, AFF1Stream],
    [ 0, AFF4_RAW_STREAM, FileBackedObject],
    ]


### Following is the high level API. See specific documentation on using these.

def load_volume(filename, autoload=True):
    """ Loads the volume in filename into the resolver.

    This function opens a volume specified in filename. The autoload
    option specifies that we should automatically load any other
    volumes which are hinted in this volume - This is usually what you
    want.

    The autoload option is also controlled by the
    GLOBAL:CONFIG_AUTOLOAD attribute.
    """
    ## Try to open the volume using all the handlers we have
    for handler in VOLUME_DISPATCH:    
        volume = handler(None, 'r')
        try:
            volume.load_from(filename)
            break
        except Exception,e:
            volume = None
            continue

    if not volume:
        DEBUG(_DEBUG, "Cant load volume %s" % e)
        return []

    ## Load identities from this volume:
    for identity_urn in oracle.resolve_list(volume.urn, AFF4_IDENTITY_STORED):
        identity = oracle.open(identity_urn, 'w')
        try:
            identity.load_encryption_keys()
        except RuntimeError: pass
        
        oracle.cache_return(identity)
    
    oracle.cache_return(volume)

    result = [volume.urn]

    ## Do we need to auto load things?
    if autoload or oracle.resolve(GLOBAL, CONFIG_AUTOLOAD):
        for v in oracle.resolve_list(volume.urn, AFF4_AUTOLOAD):
            ## Have we done this volume before (stop circular autoloads)?
            if not oracle.resolve(v, AFF4_CONTAINS):
                DEBUG(_INFO, "Autoloading %s" % v)
                try:
                    result.extend(load_volume(v))
                except Exception,e:
                    DEBUG(_WARNING, "Error occured autoloading %s: %s",
                          v, e)

    return result

def create_volume(filename):
    """ This is used to create a new volume on filename or open a
    volume for appending. We return the volume URN.
    """
    ## Try to load the volume
    load_volume(filename)
    volume_urn = oracle.resolve(filename, AFF4_CONTAINS)
    if volume_urn:
        return volume_urn
    
    volume_fd = ZipVolume(None, 'w')
    oracle.add(volume_fd.urn, AFF4_STORED, filename)
    volume_fd.finish()
    oracle.lock(volume_fd.urn, 'w')
    oracle.cache_return(volume_fd)
    
    return volume_fd.urn

def load_identity(key, cert):
    """ Creates and returns a new Identity object instantiated from
    key and cert (which might be filenames or URLs).

    Note that at a minimum you need to provide the certificate which
    will enable signing verification. If you need to actually sign new
    data, or decrypt Encrypted streams, you will also need a private
    key.
    """
    if not cert: return
    result = Identity(mode='w')
    urn = result.urn
    try:
        if key:
            result.load_priv_key(key)

        if cert:
            result.load_certificate(cert)

        result.finish()
    finally:
        oracle.cache_return(result)
    
    return result

class AFF4Image(FileLikeObject):
    """ This is the object obtained from CreateNewVolume.new_image().

    This is essentially a proxy object for the real image URN which
    must be created seperately.
    """
    def __init__(self, image_urn, volume, link=None,
                 mode='r', backing_fd=None):
        ## This is the FileLikeObject we will use to write on.
        self.image_urn = image_urn
        self.link = link
        self.mode = mode
        self.backing_fd = backing_fd
        self.volume = volume
        self.readptr = 0
        self.size = parse_int(oracle.resolve(backing_fd, AFF4_SIZE)) or 0

    def write(self, data):
        ## Its safe to close off volumes here
        while self.volume.volumes:
            volume_urn=self.volume.volumes.pop()
            volume = oracle.open(volume_urn, 'w')
            volume.close()
                
        fd = oracle.open(self.image_urn, self.mode)
        fd.seek(self.readptr)
        fd.write(data)
        self.readptr += len(data)
        oracle.cache_return(fd)

    def read(self, length):
        fd = oracle.open(self.image_urn, self.mode)
        fd.seek(self.readptr)
        data = fd.read(length)
        self.readptr += len(data)        
        oracle.cache_return(fd)

        self.readptr = min(self.readptr, self.size)
        return data
    
    def close(self):
        if self.mode != 'w': return

        fd = oracle.open(self.image_urn, self.mode)
        fd.close()

        if self.backing_fd:
            fd = oracle.open(self.backing_fd, self.mode)
            fd.close()

        ## Make a link if needed
        if self.link:
            link_urn = fully_qualified_name(self.link, self.volume.volume_urn)
            type = oracle.resolve(link_urn, AFF4_TYPE)
            if type:
                print "A %s '%s' already exists in this volume. I wont create a link now - you can add it later" % (type, link_urn)
            else:
                link = Link(link_urn)
                oracle.set(link.urn, AFF4_STORED, self.volume.volume_urn)
                oracle.set(link.urn, AFF4_TARGET, self.image_urn)
                oracle.set(link.urn, AFF4_HIGHLIGHT, _DETAILED)
                link.finish()
                link.close()

class CreateNewVolume:
    """ This create a new volume on the provided filename.

    The returned object can be used to add any new streams or maps to
    this volume. You must remember to close() all returned streams,
    and then call close() on this new volume.

    An example of how you would use this object might be:

    volume = CreateNewVolume(filename='foo.aff', encrypted=True,
                             password='foobar')
    image = volume.new_image(link = 'memory_image.dd', sparse=True)
    while 1:
        data = fd.read(1024000)
        if not data: break

        image.write(data)

    image.close()
    volume.close()
    """
    def __init__(self, filename, encrypted=False, password=None,
                 max_volume_size=0, chunks_in_segment=0):
        """ Create a new volume """
        self.encrypted = encrypted
        self.identities = []
        self.max_volume_size = max_volume_size
        self.filename = filename
        self.volumes = set()

        ## In order to be told when the volume is increased, we
        ## register our check_volume() method as an oracle set()
        ## hook. This allows us to monitor whenever anyone sets
        ## AFF4_DIRECTORY_OFFSET property on the volume.
        if max_volume_size>0:
            oracle.register_set_hook(self.check_volume)
            
        if encrypted:
            ## Make an encrypted volume
            self.container_volume_urn = create_volume(filename)

            ## This image serves as the storage for our encrypted volume
            container_image = Image(None, 'w')
            self.container_image_urn = container_image.urn
            oracle.set(self.container_image_urn, AFF4_STORED,
                       self.container_volume_urn)
            if chunks_in_segment:
                oracle.set(self.container_image_urn, AFF4_CHUNKS_IN_SEGMENT,
                           chunks_in_segment)
            ## Make sure the container does not compress (the data will be
            ## encrypted)
            oracle.set(container_image.urn, AFF4_COMPRESSION, 0)
            container_image.finish()
            oracle.cache_return(container_image)

            ## This is our encrypted stream
            encrypted_fd = Encrypted(None, 'w')
            self.encrypted_fd_urn = encrypted_fd.urn
            oracle.add(encrypted_fd.urn, AFF4_STORED, self.container_volume_urn)
            oracle.add(encrypted_fd.urn, AFF4_TARGET, self.container_image_urn)
            encrypted_fd.finish()
            oracle.cache_return(encrypted_fd)
            
            ## create a new volume inside the encrypted stream
            self.volume_urn = create_volume(encrypted_fd.urn)
        else:
            self.volume_urn = create_volume(filename)

    def new_filename(self):
        """ Produce a new volume filename for the next volume in the series.
        
        This is a seperate method in order to allow extending this
        class and implementing some other file nameing convensions.
        """
        ## Current volume number
        try:
           basename, number = self.filename.rsplit(".",1)
           number = int(number)
        except:
           number = 0
           basename = self.filename

        self.filename = "%s.%03d" % (basename, number + 1)
        return self.filename

    def check_volume(self, uri, attribute, value):
        ## If we are encrypted we only care about the container
        ## volume.
        if attribute != AFF4_DIRECTORY_OFFSET: return
        
        if self.encrypted:
            monitored_volume = self.container_volume_urn
        else:
            monitored_volume = self.volume_urn 

        ## How large is the volume?
        if uri != monitored_volume: return
        
        size = parse_int(value)
        if size > self.max_volume_size:
            ## Ok. volume is exceeded, we need to make a new volume
            new_filename = self.new_filename()
            
            ## We can not really close off any volumes here because we
            ## are called as part of the Resolver.set() function,
            ## which means that someone is writing to this volume. If
            ## we try to close() here we will cause a
            ## deadlock. Schedule the monitored_volume to be closed
            ## off later, at a more convenient time.
            self.volumes.add(monitored_volume)

            new_monitored_volume_urn = create_volume(new_filename)
            
            if self.encrypted:
                self.container_volume_urn = new_monitored_volume_urn
            else:
                self.volume_urn = new_monitored_volume_urn
                
            ## Search for all dirty objects which were written in
            ## the previous volume, and update them to the new
            ## volume:
            for urn in oracle.resolve_list(monitored_volume, AFF4_CONTAINS):
                if oracle.resolve(urn, AFF4_VOLATILE_DIRTY):
                    oracle.set(urn, AFF4_STORED, new_monitored_volume_urn)
                    oracle.add(new_monitored_volume_urn, AFF4_CONTAINS, urn)

    def add_identity(self, key, cert):
        identity = load_identity(key,cert)
        if identity:
            try:
                self.identities.append(identity.urn)
            finally:
                oracle.cache_return(identity)
        
    def new_image(self, link=None, sparse=False, compression=True):
        """ Call this to obtain a new AFF4Image object. Remember to call
        close() on that object before calling close() on the volume.
        """
        if sparse:
            ## The backing image provides storage
            map_fd = Map(None, 'w')
            image = Image(None, 'w')
            
            ## Make the storage object clearly related to the map
            image.urn = "%s/storage" % map_fd.urn
            oracle.add(image.urn, AFF4_STORED, self.volume_urn)
            if not compression:
                oracle.set(image.urn, AFF4_COMPRESSION, 0)
            image.finish()
            oracle.cache_return(image)

            ## The Map stream provides the sparse interface
            oracle.set(map_fd.urn, AFF4_STORED, self.volume_urn)
            oracle.set(map_fd.urn, AFF4_TARGET, image.urn)
            oracle.set(map_fd.urn, AFF4_HIGHLIGHT, _DETAILED)
            map_fd.finish()

            return AFF4Image(map_fd.urn, self, link=link,
                             mode='w', backing_fd=image.urn,
                             )
        else:
            image_fd = Image(None, 'w')
            oracle.add(image_fd.urn, AFF4_STORED, self.volume_urn)
            oracle.set(image_fd.urn, AFF4_HIGHLIGHT, _DETAILED)
            image_fd.finish()
            oracle.cache_return(image_fd)

            return AFF4Image(image_fd.urn, self, link=link,
                             mode='w')

    def sync_identities(self):
        ## Write off any Identities we may have
        for i in self.identities:
            identity = oracle.open(i, 'w')                            
            try:
                if self.encrypted:
                    ## Encrypted streams need some stuff in the container
                    ## volume (like keys)
                    oracle.set(identity.urn, AFF4_STORED, self.container_volume_urn)
                    identity.save_encryption_keys()
                else:
                    oracle.set(identity.urn, AFF4_STORED, self.volume_urn)
                    
                identity.close()
            finally:
                oracle.cache_return(identity)

    def close(self):
        self.sync_identities()
        self.volumes.add(self.volume_urn)

        ## We need to do this as the set might change as a result of
        ## closing the volume if a new volume needs to be created for
        ## property files etc.
        while self.volumes:
            volume_urn = self.volumes.pop()
            volume = oracle.open(volume_urn, 'w')
            volume.close()

        if self.encrypted:
            ## Make sure the encrypted volume is autoloaded when the container
            ## volume is opened
            oracle.set(self.container_volume_urn, AFF4_AUTOLOAD, self.encrypted_fd_urn)

            volume = oracle.open(self.container_volume_urn, 'w')
            volume.close()
        
## Set up some defaults
oracle.set(GLOBAL, CONFIG_VERBOSE, _INFO)
oracle.set(GLOBAL, CONFIG_THREADS, "1")
oracle.set(GLOBAL, CONFIG_AUTOLOAD, 'yes')

## Some well known objects
oracle.set(AFF4_SPECIAL_URN_NULL, AFF4_TYPE, AFF4_ERROR_STREAM)
oracle.set(AFF4_SPECIAL_URN_NULL, CONFIG_PAD, 1)
oracle.set(AFF4_SPECIAL_URN_ZERO, AFF4_TYPE, AFF4_ERROR_STREAM)
oracle.set(AFF4_SPECIAL_URN_ZERO, CONFIG_PAD, 1)

#def DEBUG(verb, fmt, *args):
#    if verb <= _DEBUG:
#        print fmt % args
