#!/usr/bin/env python
""" This is an implementation of Magic file header detection.

The standard Magic scheme is not powerful enough to correctly identify
some file types accurately. We try to improve upon it here.

This is a score based system - each magic handler gets the opportunity
to score the data. This represents our confidence in the
identification. If a score is bigger or equal to 100% it wins
automatically. Otherwise the highest score wins.

The usual tests include a set of regexs to be run over the file
header, but other tests are also possible.
"""
import index, pdb
import pyflag.Registry as Registry
import pyflag.DB as DB
import pyflag.pyflaglog as pyflaglog

class MagicResolver:
    """ This is a highlander class to manage access to all the resolvers """
    indexer = None
    index_map = {}
    rule_map = {}
    count = 0
    magic_handlers = []

    def __init__(self):
        """ We keep a record of all magic handlers and instantiate them all.
        """
        if not MagicResolver.indexer:
            MagicResolver.indexer = index.Index()
            for cls in Registry.MAGIC_HANDLERS.classes:
                cls = cls()
                MagicResolver.magic_handlers.append(cls)
                for rule in cls.regex_rules:
                    MagicResolver.indexer.add_word(rule[0], MagicResolver.count, index.WORD_EXTENDED)
                    MagicResolver.index_map[MagicResolver.count] = cls
                    MagicResolver.rule_map[MagicResolver.count] = rule
                    MagicResolver.count += 1

                for rule in cls.literal_rules:
                    MagicResolver.indexer.add_word(rule[0], MagicResolver.count, index.WORD_ENGLISH)
                    MagicResolver.index_map[MagicResolver.count] = cls
                    MagicResolver.rule_map[MagicResolver.count] = rule
                    MagicResolver.count += 1

            pyflaglog.log(pyflaglog.DEBUG,"Loaded %s signatures into Magic engine" % MagicResolver.count)
            
    def estimate_type(self, fd):
        """ Given the data we guess the best type determination. 
        """
        scores = {}
        max_score = [0, None]
        pending = set(self.rule_map.keys())

        fd.seek(0)
        data = fd.read(1024)

        
        ## Give all handlers a chance to rate the data
        for cls in self.magic_handlers:
            scores[cls.__class__.__name__] = cls.score(fd, data)
            
            ## Maintain the higher score in the list:
            if scores[cls.__class__.__name__] > max_score[0]:
                max_score = [ scores[cls.__class__.__name__], cls]

        ## Index the data using the indexer:
        ## Get some data to match in our rules
        for offset, matches in self.indexer.index_buffer(data, unique=0):
            for match in matches:
                ## match is (rule_id, offset, length)
                ## Thats the rule that matched:
                if match[0] not in pending:
                    continue

                rule = self.rule_map[match[0]]
                cls = self.index_map[match[0]]
            
                ## Is there a range or a specific offset?
                try:
                    rng = rule[1]
                    if offset >= rng[0] and offset <= rng[1]:
                        scores[cls.__class__.__name__] += cls.score_hit(data, match, pending)
                except IndexError:
                    if offset == rule[1]:
                        scores[cls.__class__.__name__] += cls.score_hit(data, match, pending)
            
                ## Maintain the higher score in the list:
                if scores[cls.__class__.__name__] > max_score[0]:
                    max_score = [ scores[cls.__class__.__name__], cls]

                ## When one of the scores is big enough we quit:
                if max_score[0] >= 100:
                    break

            if max_score[0] >= 100:
                break
            
        ## Return the highest score:
        return max_score, scores

    def find_inode_magic(self, case, inode_id=None, urn=None):
        """ A convenience function to resolve an inode's magic.

        We check the db cache first.
        """
        if urn:
            import pyflag.aff4.aff4 as aff4
            
            inode_id = aff4.oracle.get_id_by_urn(urn)
            if not inode_id:
                raise IOError("Unknown URN %s" % urn)
            
        ## Is it already in the type table?
        import pyflag.FileSystem as FileSystem

        fsfd = FileSystem.DBFS(case)
        fd = fsfd.open(inode_id = inode_id)
        max_score, scores = self.estimate_type(fd)
        
        return max_score[1].type_str(), max_score[1].mime_str(), scores

import pyflag.aff4.aff4 as aff4
from pyflag.aff4.pyflag_attributes import *

def set_magic(case, inode_id, magic, mime=None):
    """ Set the magic string on the inode """
    urn = aff4.oracle.get_urn_by_id(inode_id)
    
    aff4.oracle.set(urn, PYFLAG_TYPE, magic)

#     args = dict(inode_id=inode_id,
#                 type = magic)
#     if mime:
#         args['mime'] = mime

#     dbh = DB.DBO(case)
#     dbh.update("type", where="inode_id = '%s'" % inode_id,
#                **args)
#     if dbh.cursor.rowcount == 0:
#             dbh.insert("type", **args)

class Magic:
    """ This is the base class for all Magic handlers. """
    ## The default type and mime strings
    type = None
    mime = 'application/octet-stream'
    default_score = 100

    ## Note that these must be unique to this Magic instance since the
    ## indexer uses the unique IDs to identify this class. This might
    ## be a future limitation.
    regex_rules = []
    literal_rules = []

    ## These are unit tests for verification
    samples = []
    
    def type_str(self):
        return self.type

    def mime_str(self):
        return self.mime
    
    def score(self, fd, data):
        """ This is called on each class asking them to score the data """
        return 0

    def score_hit(self, data, match, pending):
        """ This is only called when an indexer hit is made """
        return self.default_score
    
