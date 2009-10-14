""" These are PreCanned Reports.

PreCanned Reports are the PyFlag equivalent of the google 'Im Feeling
Lucky' feature - we basically just dump out some simple queries which
are used to get you started.
"""

import pyflag.Reports as Reports
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.Registry as Registry

class ImFeelingLucky(Reports.report):
    """
    'Im Feeling Lucky' is a report which does basic analysis to get
    you started on the case. Select which kind of analysis you want to
    do.
    """
    name = "Im Feeling Lucky"
    family = "Disk Forensics"

    def get_names(self, cls):
        if type(cls.name)==str:
            names = [cls.name,]
        else:
            names = cls.name
                    
        return names

    def display(self, query, result):
        query.clear('filter')
        def left_pane_cb(path):
            ## We expect a directory here:
            if not path.endswith('/'): path=path+'/'

            seen = []
            result = []
            for cls in Registry.PRECANNED.classes:
                if not cls.name: continue
                
                for name in self.get_names(cls):
                    if name.startswith(path):
                        branches = name[len(path):].split('/')
                        branch = branches[0]
                        if branch not in seen:
                            seen.append(branch)
                            if len(branches)>1:
                                result.append((branch, branch, "branch"))
                            else:
                                result.append((branch, branch, "leaf"))

            return result
            
        def right_pane_cb(path, result):
            for cls in Registry.PRECANNED.classes:
                for name in self.get_names(cls):
                    if name == path:
                        query.set("open_tree",path)
                        cls().display(query, result)
                        return

            result.heading("Precanned Analysis")
            result.para("Select the type of automated analysis required. You can use this to get you started, and then drive the analysis further.")

        result.tree(tree_cb = left_pane_cb, pane_cb = right_pane_cb)

class Images(Reports.PreCannedCaseTableReports):
    """ Display a preview of images """
    args = {'filter':' "Thumb"  has_magic image and  "Size"  > 20000 ',
            'order': 1, 'direction':0}
    family = "Disk Forensics"
    description = "View all images bigger than 20kb "
    name = "/Disk Forensics/Multimedia/Graphics"
    default_table = "AFF4VFS"
    columns = ['Thumb', 'Size','Filename']

class Videos(Images):
    """ Display a preview of Videos """
    args = {'filter':' "Thumb"  has_magic video',
            'order': 1, 'direction':0}
    description = "View all Videos "
    name = "/Disk Forensics/Multimedia/Videos"

class OfficeFiles(Images):
    """ Display a preview of Office files """
    args = {'filter':' "Thumb"  has_magic office ',
            'order': 1, 'direction':0}
    description = "View all Office files "
    name = "/Disk Forensics/Multimedia/Office"

class HTMLPages(Images):
    args = {'filter':' "Thumb"  has_magic HTML ',
            'order': 4, 'direction':1}
    description = "View all HTML Pages "
    name = "/Disk Forensics/Multimedia/HTML Pages"

class HTMLURLs(Reports.PreCannedCaseTableReports):
    args = {'filter': '"Content Type" contains html and Status = 200 ',
            '_hidden': [ 4, 5, 6] }
    report='Browse HTTP Requests'
    family='Network Forensics'
    description = 'View all HTML URLs'
    name = [ "/Network Forensics/Web Applications/HTML URLs" ]
    default_table = 'HTTPCaseTable'
    columns = ['Timestamp', 'Inode', 'Method', 'TLD', 'URL', 'Content Type', 'InodeTable.Size', 'Status']

class ImageURLs(Reports.PreCannedCaseTableReports):
    description = "Show larger images transferred over HTTP"
    name = [ "/Network Forensics/Communications/Web/Images"]
    family = 'Network Forensics'
    args = {'filter':'Thumb has_magic image and Size > 20000',
            'order': 0, 'direction': 1 }
    default_table = 'AFF4VFS'
    columns = ['Modified','Thumb','Size', 'HTTPCaseTable.TLD', 'HTTPCaseTable.URL']

class VideoURLs(ImageURLs):
    description = "Show videos downloaded over HTTP"
    name = [ "/Network Forensics/Communications/Web/Videos"]
    args = {'filter':'Thumb has_magic video',
            'order': 0, 'direction': 1 }

class GoogleSearches(Reports.PreCannedCaseTableReports):
    description = "Shows possible Google searches."
    name = [ "/Network Forensics/Web Applications/Google Searches" ]
    family = 'Network Forensics'
    args = {'filter': 'Parameter = q and "Content Type" contains html', '_hidden': 5}
    default_table = 'HTTPCaseTable'
    columns = ['AFF4VFS.Modified',
               'URN',
               'HTTPParameterCaseTable.Parameter',
               'HTTPParameterCaseTable.Value',
               'URL',
               'Content Type']
