#!/usr/bin/python
import aff4
from aff4_attributes import *
import tdb_resolver

aff4.oracle = tdb_resolver.TDBResolver()

import optparse, pdb
import sys, os

parser = optparse.OptionParser()
parser.add_option("-i", "--image", default=None,
                  action='store_true',
                  help = "Imaging mode")

parser.add_option("-m", "--max_size", default=0, type=int,
                  help = "Try to change volumes after the volume is bigger than this size")

parser.add_option("-o", "--output", default=None,
                  help="Create the output volume on this file or URL (using webdav)")

parser.add_option("", "--link", default="default",
                  help="Create a symbolic link to the image URN with this name")

parser.add_option("-D","--dump", default=None,
                  help="Dump out this stream (to --output or stdout)")

parser.add_option("","--chunks_in_segment", default=0, type='int',
                  help="Total number of chunks in each bevy")

parser.add_option("","--nocompress", default=False, action='store_true',
                  help="Do not Compress image")

## This is needed to support globbing for -l option
def vararg_callback(option, opt_str, value, parser):
    assert value is None
    value = []
    
    for arg in parser.rargs:
        # stop on --foo like options
        if arg[:2] == "--" and len(arg) > 2:
            break

        ## stop on -f like options
        if arg[:1] == "-" and len(arg) > 1:
            break
        
        value.append(arg)
            
    del parser.rargs[:len(value)]
    try:
        getattr(parser.values, option.dest).append(value)
    except:
        setattr(parser.values, option.dest, value)

parser.add_option("-l","--load", default=[], dest="load",
                  action = "callback", callback=vararg_callback,
                  help="Load this volume to prepopulate the resolver")

parser.add_option("-I", "--info", default=None,
                  action = 'store_true',
                  help="Information mode - dump all information in the resolver")

parser.add_option("-V", "--verify", default=None,
                  action = 'store_true',
                  help="Verify all signatures and hashes when in --info mode")

parser.add_option("-k", "--key", default=None,
                  help="Key file to use (in PEM format)")

parser.add_option("-c", "--cert", default=None,
                  help="Certificate file to use (in PEM format)")

parser.add_option("-t", "--threads", default=2,
                  help="Number of threads to use")

parser.add_option('-v', '--verbosity', default=5,
                  help="Verbosity")

parser.add_option('-e', '--encrypt', default=False,
                  action = 'store_true',
                  help="Encrypt the image")

parser.add_option("-p", "--password", default='',
                  help='Use this password instead of prompting')

(options, args) = parser.parse_args()
    
## Load defaults into configuration space
aff4.oracle.set(GLOBAL, CONFIG_THREADS, options.threads)
aff4.oracle.set(GLOBAL, CONFIG_VERBOSE, options.verbosity)

if options.password:
    aff4.oracle.set(GLOBAL, AFF4_VOLATILE_PASSPHRASE, options.password)

## Prepare an identity for signing
IDENTITY = aff4.load_identity(options.key, options.cert)

VOLUMES = []
for volume_set in options.load:
    loaded_volume_set = []
    for v in volume_set:
        loaded_volume_set.extend(load_volume(v))

    if len(loaded_volume_set)>1:
        ## Make a combined stream
        m = Map(None, 'w')
        m.urn  = loaded_volume_set[0] + "/combined"
        aff4.oracle.set(m.urn, AFF4_STORED, AFF4_SPECIAL_URN_NULL)
        aff4.oracle.set(m.urn, AFF4_HIGHLIGHT, 7)
        m.finish()
        m.mode = 'r'

        ## Add the image to the map
        for t in loaded_volume_set:
            m.write_from(t, 0, aff4.oracle.resolve(t, AFF4_SIZE))

        aff4.oracle.set(m.urn, AFF4_SIZE, m.size)

        ## The map is ready for use
        aff4.oracle.cache_return(m)
        
    VOLUMES.extend(loaded_volume_set)

## Use the high level interface to get what we want:
if options.image:
    os.environ['AFF4_FILEPATH'] = '/'
    ## Imaging mode
    volume = aff4.CreateNewVolume(options.output, encrypted=options.encrypt,
                                  password=options.password,
                                  chunks_in_segment=options.chunks_in_segment,
                                  max_volume_size = options.max_size)

    ## Add any identities needed
    volume.add_identity(options.key, options.cert)
    
    for in_urn in args:
        image = volume.new_image(link = options.link, sparse=True,
                                 compression=not options.nocompress)
        if "://" not in in_urn:
            in_urn = "file://%s" % in_urn

        in_fd = aff4.oracle.open(in_urn)
        while 1:
            data = in_fd.read(1024 * 1024)
            if not data: break
            
            image.write(data)
        image.close()

    volume.close()

elif options.dump:
    ## Look for the right stream in one of the volumes
    for v in VOLUMES:
        stream = aff4.oracle.open(fully_qualified_name(options.dump, v), 'r')
        if stream: break

    output = options.output
    if output:
        if "://" not in output:
            output = "file://%s" % output
        output_fd = FileBackedObject(output, 'w')
    else:
        output_fd = sys.stdout
        
    try:
        while 1:
            data = stream.read(1024 * 1024)
            if not data: break

            output_fd.write(data)
    finally:
        aff4.oracle.cache_return(stream)
        if output:
            output_fd.close()
            
elif options.info:
    print aff4.oracle
    
elif options.verify:
    ## Scan all volumes for identities
    for volume_urn in VOLUMES:
        for identity_urn in aff4.oracle.resolve_list(volume_urn, AFF4_IDENTITY_STORED):
            ## Open each identity and verify it
            identity = aff4.oracle.open(identity_urn, 'r')
            try:
                print "\n****** Identity %s verifies *****" % identity_urn
                print "    CN: %s \n" % identity.x509.get_subject().as_text()
                def print_result(uri, attribute, value, calculated):
                    if value == calculated:
                        print "OK  %s (%s)" % (uri, value.encode("hex"))
                    else:
                        print "WRONG HASH DETECTED in %s (found %s, should be %s)" % \
                              (uri, calculated.encode("hex"), value.encode("hex"))

                identity.verify(verify_cb = print_result)
            finally: aff4.oracle.cache_return(identity)
else:
    print "You must specify a mode (try -h)"
    
