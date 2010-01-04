""" This is a module to provide an interface to AFFLIB - the old AFF1
implementation.
"""

from ctypes import *
import ctypes.util

possible_names = ['afflib',]
for name in possible_names:
    resolved = ctypes.util.find_library(name)
    if resolved:
        break

try:
    if resolved == None:
        raise ImportError("afflib not found")
    afflib = CDLL(resolved)
    if not afflib._name: raise OSError()
except OSError:
    raise ImportError("afflib not found")

class afffile:
    """ A file like object to provide access to the aff file """
    def __init__(self, volume):
        self.handle = afflib.af_open(volume, c_int(0),
                                     c_int(0))
        if self.handle==0:
            raise RuntimeError("Unable to open aff file")

        self.readptr = 0
        self.size = afflib.af_get_imagesize(self.handle)
        
    def seek(self, offset, whence=0):
        if whence==0:
            self.readptr = offset
        elif whence==1:
            self.readptr += offset
        elif whence==2:
            self.readptr = self.size + offset

        self.readptr = min(self.readptr, self.size)

    def tell(self):
        return self.readptr

    def read(self, length):
        buf = create_string_buffer(length)
        afflib.af_seek(self.handle, c_ulonglong(self.readptr), 0)
        length = afflib.af_read(self.handle, buf,
                                c_ulong(length))

        return buf.raw[:length]

    def close(self):
        afflib.af_close(self.handle)
        self.handle = None
        
    def get_headers(self):
        afflib.af_rewind_seg(self.handle)
        result = {}
        while 1:
        ## Iterate over all segments and print those which are not pages
            segname = create_string_buffer(1024)
            segname_length = pointer(c_ulong(1024))

            data = create_string_buffer(1024)
            data_len = pointer(c_ulong(1024))

            res = afflib.af_get_next_seg(self.handle, segname, segname_length,
                                         c_ulong(0), data, data_len)
            if res==-2:
                afflib.af_get_next_seg(self.handle, segname, segname_length,
                                       c_ulong(0), c_ulong(0), c_ulong(0))
            elif res==0:
                key = segname.value
                if not key.startswith('page'):
                    result[segname.value] = data.value
            else:
                break

        return result


def aff_open(volumes):
    return afffile(volumes)

if __name__=="__main__":
##    fd = afffile("/var/tmp/uploads/testimages/xp-laptop-2005-06-25.aff")
    fd = afffile("pyflag_stdimage_0.5.e01")
    print fd.get_headers()
    fd.seek(0x8E4B88)
    print "%r" % fd.read(100)
