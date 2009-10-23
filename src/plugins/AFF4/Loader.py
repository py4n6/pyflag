""" This module presents lots of GUIs to build AFF4 objects.

This is not really necessary since aff4 tools can be used on the
command line to do the same thing.

The basic result is that a new AFF4 object is created in the case
volume
"""
import pyflag.Reports as Reports
import pyflag.CacheManager as CacheManager
import pyflag.aff4.aff4 as aff4
import pyflag.FlagFramework as FlagFramework
import pdb

class LoadVolume(Reports.report):
    """ Creates a new AFF4 object in the VFS. """
    name = 'Load Volume'
    family = 'Load Data'

    def display(self, query, result):
        result.start_form(query)
        result.heading("Load Volume")
        self.render_form(query, result)
        result.end_form('Submit')

    def render_form(self, query,result):
        try:
            if query["__submit__"]:
                new_fd = CacheManager.AFF4_MANAGER.create_cache_map(
                    query['case'], FlagFramework.normpath(query['name']))

                for f in query.getarray('files'):
                    fd = aff4.oracle.open(f)
                    new_fd.write_from(fd.urn, 0, fd.size)

                new_fd.close()
                
        except KeyError:
            result.fileselector("Select files to load", 'files')
            result.text("Files will be logically concatenated in the order selected")
            result.textfield("Name of object in VFS",'name')
