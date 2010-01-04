""" This module handles automatic loading of partition tables.
"""

import pyflag.Scanner as Scanner
import pyflag.DB as DB
import pyflag.FileSystem as FileSystem
import pyflag.pyflaglog as pyflaglog
import pyflag.CacheManager as CacheManager
import pdb
import sk
import pyflag.Magic as Magic
import pyflag.FlagFramework as FlagFramework

SECTOR_SIZE = 512

class PartitionScanner(Scanner.GenScanFactory):
    """ Detects partitions in the image and creates VFS nodes for them.
    """
    default = True
    group = "Disk Forensics"

    def scan(self, fd, scanners, type, mime, cookie, scores=None, **args):
        if 'x86 boot sector' in type:
            try:
                parts = sk.mmls(fd)
            except IOError,e:
                print e
                return

            for part in parts:
                ## Make a unique and sensible name for this partition
                name = "%s @ 0x%X" % (part[2], part[0])

                ## Add new maps for each partition
                map = CacheManager.AFF4_MANAGER.create_cache_map(
                    fd.case,
                    "%s/%s" % (fd.urn.parser.query, name))

                map.write_from(fd.urn, SECTOR_SIZE * part[0],
                               SECTOR_SIZE * part[1])

                map.close()

                ## Now we recursively scan each object
                fsfd = FileSystem.DBFS(fd.case)
                new_fd = fsfd.open(inode_id = map.inode_id)
                try:
                    fs = sk.skfs(new_fd)
                    fs.close()

                    ## Lets add a hint
                    Magic.set_magic(fd.case,
                                    inode_id = map.inode_id,
                                    mime = "application/filesystem",
                                    magic = "Filesystem")

                except: pass

                Scanner.scan_inode_distributed(fd.case, map.inode_id,
                                               scanners, cookie)

class FilesystemLoader(Scanner.GenScanFactory):
    """ A Scanner to automatically load filesystem """
    def create_map(self, fd, fs, skfs_inode, path):
        block_size = fs.block_size

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
            fd.case,
            "%s/__inodes__/%s" % (fd.urn.parser.query, skfs_inode),
            size = size, target = fd.urn,
            status=status)

        for block in skfd.blocks():
            map.write_from(fd.urn, block * block_size, block_size)

        ## update the size of the map
        map.size.set(size)

        CacheManager.AFF4_MANAGER.create_link(
            fd.case,
            map.urn, FlagFramework.sane_join(fd.urn.parser.query, path))

        map.close()

    def scan(self, fd, scanners, type, mime, cookie, scores=None, **args):
        if 'Filesystem' in type:
            print "Will load %s" % fd.urn.value
            fs = sk.skfs(fd)

            for root, dirs, files in fs.walk('/', unalloc=True, inodes=True):
                for d, dirname in dirs:
                    self.create_map(fd, fs, d, FlagFramework.sane_join(root[1], dirname))

                for f, filename in files:
                    self.create_map(fd, fs, f, FlagFramework.sane_join(root[1], filename))


## UnitTests:
import unittest
import pyflag.pyflagsh as pyflagsh
import pyflag.tests

class PartitionTest(pyflag.tests.ScannerTest):
    """ Test Partition scanner and Filesystem loader """
    test_case = "PyFlagTestCase"
    test_file = "pyflag_stdimage_0.5.e01"

    def test01PartitionScan(self):
        """ Check the Partition scanner works """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'*'])
