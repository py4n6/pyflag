""" This module handles automatic loading of partition tables.
"""

import pyflag.Scanner as Scanner
import pyflag.DB as DB
import pyflag.FileSystem as FileSystem
import pyflag.pyflaglog as pyflaglog
import pyflag.CacheManager as CacheManager
import pdb
import sk

SECTOR_SIZE = 512

class PartitionScanner(Scanner.GenScanFactory):
    """ Detects partitions in the image and creates VFS nodes for them.
    """

    def scan(self, fd, factories, type, mime):
        if 'x86 boot sector' in type:
            try:
                parts = sk.mmls(fd)
            except IOError,e:
                print e
                return

            names = set()
            for part in parts:
                count = 1
                name = part[2]
                while name in names:
                    name = "%s %u" % (part[2], count)
                    count +=1

                names.add(name)
                ## Add new maps for each partition
                map = CacheManager.AFF4_MANAGER.create_cache_map(
                    self.case,
                    "%s/%s" % (fd.urn, name))

                map.write_from(fd.urn, SECTOR_SIZE * part[0],
                               SECTOR_SIZE * part[1])

                map.close()

                ## Now we recursively scan each object
                new_fd = self.fsfd.open(inode_id = map.inode_id)
                try:
                    fs = sk.skfs(new_fd)
                    fs.close()
                    dbh = DB.DBO(self.case)
                    dbh.insert("type",
                               inode_id = map.inode_id,
                               mime = "application/filesystem",
                               type = "Filesystem")
                except: pass

                Scanner.scan_inode(self.case, map.inode_id,
                                   factories)
                

class FilesystemLoader(Scanner.GenScanFactory):
    """ A Scanner to automatically load filesystem """
    def scan(self, fd, factories, type, mime):
        if 'Filesystem' in type:
            print "Will load %s" % fd.urn

            fs = sk.skfs(fd)
            block_size = fs.block_size
            def create_map(skfs_inode, path):
                if str(skfs_inode) == "0-0-0":
                    return 1
                
                if skfs_inode.alloc:
                    status = 'alloc'
                else:
                    status = 'deleted'

                ## Add the map under the path
                skfd = fs.open(inode=skfs_inode)
                skfd.seek(0,2)
                size = skfd.tell()
                map = CacheManager.AFF4_MANAGER.create_cache_map(
                    self.case,
                    "%s/__inodes__/%s" % (fd.urn, skfs_inode),
                    size = size,
                    status=status)

                for block in skfd.blocks():
                    map.write_from(fd.urn, block * block_size, block_size)

                CacheManager.AFF4_MANAGER.create_link(
                    self.case,
                    map.urn, DB.expand("%s/%s",(fd.urn, path)))
                map.close()
            
            for root, dirs, files in fs.walk('/', unalloc=True, inodes=True):
                for d, dirname in dirs:
                    create_map(d, DB.expand("%s/%s", (root[1], dirname)))
                    
                for f, filename in files:
                    create_map(f, DB.expand("%s/%s", (root[1], filename)))
