#!/usr/bin/python2.6

from aff4 import *
import stat
from errno import *
import pdb

# pull in some spaghetti to make this stuff work without fuse-py being installed
try:
    import _find_fuse_parts
except ImportError:
    pass
import fuse
from fuse import Fuse

if not hasattr(fuse, '__version__'):
    raise RuntimeError, \
        "your fuse-py doesn't know of fuse.__version__, probably it's too old."

fuse.fuse_python_api = (0, 2)

fuse.feature_assert('stateful_files', 'has_init')

VOLUMES =[]

class AFF4Fuse(Fuse):
    """ A class that makes the AFF4 objects appear in a fuse
    filesystem"""
    
    def __init__(self, *args, **kw):
        Fuse.__init__(self, *args, **kw)
        self.root = '/'

    def getxattr(self, path, name, size):       
        value = oracle.resolve(path, name) or ''
        if size==0:
            return len(value)
        
        return value
   
    def listxattr(self, path, size):
        urn = self.find_urn(path)
        
        aa = ["user." + a for a in ("foo", "bar")]
        if size == 0:
            # We are asked for size of the attr list, ie. joint size of attrs
            # plus null separators.
            return len("".join(aa)) + len(aa)
        
        return aa

    def find_urn(self, path):
        """ Resolves path back to a fully qualified URN """
        ## It must be a full object
        for v in VOLUMES:
            urn = fully_qualified_name(path, v)
            if not oracle.resolve(urn, AFF4_TYPE): continue

            return urn
        

    def getattr(self, path):
        path = path[1:]
        s = fuse.Stat()
        s.st_mode = 0100644
        s.st_ino = 1
        s.st_dev = 0
        s.st_nlink = 0
        s.st_uid = 0
        s.st_gid = 0
        s.st_size = 0
        s.st_atime = 0
        s.st_mtime = 0
        s.st_ctime = 0
        s.st_blocks = 0
        s.st_blksize = 4096
        s.st_rdev = 0

        ## Is this a directory?
        sub_dir = self.list_dir(path)
        print "sub_dir of %s: %s" %( path,sub_dir)
        if sub_dir:
            s.st_mode = 040755
            return s
        
        urn = self.find_urn(path)
        s.st_size = parse_int(oracle.resolve(urn, AFF4_SIZE))
        s.st_atime = s.st_mtime = s.st_ctime = parse_int(oracle.resolve(urn, AFF4_TIMESTAMP))

        return s

    def is_dir(self, path):
        path = path[1:]
        for v in VOLUMES:
            virtual_path = fully_qualified_name(path, v)
            if oracle.resolve(virtual_path, AFF4_TYPE):
                return False

        return True

    display_types = [ relative_name(AFF4_MAP, NAMESPACE),
                      relative_name(AFF4_LINK, NAMESPACE),
                      relative_name(AFF4_IMAGE, NAMESPACE)]

    def list_dir(self, path):
        if path.startswith("/"):
            path = path[1:]
        urns = oracle.urn.keys()
        result = set()
        print "Will list path %s" % path
        for e in urns:
            if not e: continue
            global VOLUMES
            virtual_path = e
            for v in VOLUMES:
                if e.startswith(v):
                    virtual_path = relative_name(e, v)
                    break

            if virtual_path.startswith(path):
                ## Only show some streams
                type = oracle.resolve(e, AFF4_TYPE)
                new_path = virtual_path[len(path):]
                if type in self.display_types and new_path:
                    new_path = os.path.normpath(new_path)
                    if new_path.startswith("/"):
                        new_path = new_path[1:]
                        
                    result.add(new_path.split("/")[0])

        return result
    
    def readlink(self, path):
        return os.readlink("." + path)

    def readdir(self, path, offset):    
        for i in self.list_dir(path):
            result = fuse.Direntry(i)
            if self.list_dir(os.path.join(path, i)):
                result.type = stat.S_IFDIR
            else:
                result.type = stat.S_IFREG
                
            yield result

    def unlink(self, path):
        pass

    def rmdir(self, path):
        pass

    def symlink(self, path, path1):
        pass

    def rename(self, path, path1):
        pass

    def link(self, path, path1):
        pass

    def chmod(self, path, mode):
        pass

    def chown(self, path, user, group):
        pass

    def truncate(self, path, len):
        pass
    
    def mknod(self, path, mode, dev):
        pass

    def mkdir(self, path, mode):
        pass

    def utime(self, path, times):
        pass

    def access(self, path, mode):
        pass

    def statfs(self):
        """
        Should return an object with statvfs attributes (f_bsize, f_frsize...).
        Eg., the return value of os.statvfs() is such a thing (since py 2.2).
        If you are not reusing an existing statvfs object, start with
        fuse.StatVFS(), and define the attributes.

        To provide usable information (ie., you want sensible df(1)
        output, you are suggested to specify the following attributes:

            - f_bsize - preferred size of file blocks, in bytes
            - f_frsize - fundamental size of file blcoks, in bytes
                [if you have no idea, use the same as blocksize]
            - f_blocks - total number of blocks in the filesystem
            - f_bfree - number of free blocks
            - f_files - total number of file inodes
            - f_ffree - nunber of free file inodes
        """
        s=fuse.StatVfs()
        s.f_bsize = 4096
        s.f_frsize = 4096
        s.f_blocks = 1
        s.f_bfree = 0
        s.f_files = len(oracle.urn.keys())
        s.f_ffree = 0
        
        return s

    def fsinit(self):
        pass

    class AFF4FuseFile(object):
        """ This is a file created on the AFF4 universe """
        direct_io = False
        keep_cache = True

        def __init__(self, path, flags, *mode):
            self.path = path
            path = path[1:]
            for v in VOLUMES:
                self.urn = fully_qualified_name(path, v)
                if oracle.resolve(self.urn, AFF4_TYPE): break

            ## Check that the object can be opened
            obj = oracle.open(self.urn, 'r')
            if not obj:
                raise IOError("unable to find AFF4 object %s" % path)
            oracle.cache_return(obj)

        def read(self, length, offset):
            print length, offset,
            fd = oracle.open(self.urn, 'r')
            try:
                fd.seek(offset)
                data = fd.read(length)
                print len(data)
                return data
            finally:
                oracle.cache_return(fd)


        def _fflush(self):
            pass

        def fsync(self, isfsyncfile):
            pass
        
        def flush(self):
            pass
        
        def fgetattr(self):
            return os.stat(self.path)

        def ftruncate(self, len):
            pass

        def lock(self, cmd, owner, **kw):
            return -EOPNOTSUPP

    def main(self, *a, **kw):
        self.file_class = self.AFF4FuseFile
        return Fuse.main(self, *a, **kw)

def main():
    global server
    usage = """
Userspace nullfs-alike: mirror the filesystem tree from some point on.

""" + Fuse.fusage

    server = AFF4Fuse(version="%prog " + fuse.__version__,
                 usage=usage,
                 dash_s_do='setsingle')

    # Disable multithreading: if you want to use it, protect all method of
    # XmlFile class with locks, in order to prevent race conditions
    server.multithreaded = False

    server.parser.add_option(mountopt="root", metavar="PATH", default='/',
                             help="mirror filesystem from under PATH [default: %default]")
    
    server.parser.add_option(mountopt="load", metavar="FILE,FILE,FILE", default=[],
                             help="Load these AFF4 volumes to populate the filesystem")

    server.parser.add_option(mountopt="key", metavar="FILE", default=None,
                             help="x509 key")

    server.parser.add_option(mountopt="cert", metavar="FILE", default=None,
                             help="x509 cert")
    
    server.parse(values = server, errex=1)

    ## Try to fix up the mount point if it was given relative to the
    ## CWD
    if not os.access(os.path.join("/",server.fuse_args.mountpoint), os.W_OK):
        server.fuse_args.mountpoint = os.path.join(os.getcwd(), server.fuse_args.mountpoint)

    ## Prepare an identity for signing
    try:
        IDENTITY = load_identity(server.key, server.cert)
    except AttributeError: pass
    
    ## Load all the volumes FIXME - support more than one volume
    for v in server.load.split(","):
        global VOLUMES
        VOLUMES = load_volume(v)

    try:
        if server.fuse_args.mount_expected():
            os.chdir(server.root)
    except OSError:
        print >> sys.stderr, "can't enter root of underlying filesystem"
        sys.exit(1)

    server.main()

if __name__ == '__main__':
    main()
