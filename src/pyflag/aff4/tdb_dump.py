""" This program lists the attrbiutes for a particular URN """
import tdb_resolver, aff4
from optparse import OptionParser
import sys

aff4.oracle = tdb_resolver.TDBResolver()

try:
    print aff4.oracle.export(sys.argv[1])
except IndexError:
    print aff4.oracle.export_all()
