## Common attributes - part of the AFF4 standard

## namespaces
NAMESPACE = "aff4:" ## AFF4 namespace
VOLATILE_NS = "aff4volatile:" ## Never written to files
CONFIGURATION_NS = VOLATILE_NS + "config:" ## Used to configure the
                                           ## library with global
                                           ## settings
FQN = "urn:" + NAMESPACE

GLOBAL = VOLATILE_NS + "global" ## A special urn representing the
                                ## global context

#Configuration parameters
CONFIG_THREADS = CONFIGURATION_NS + "threads"
CONFIG_VERBOSE = CONFIGURATION_NS + "verbosity"
CONFIG_AUTOLOAD = CONFIGURATION_NS + "autoload"
CONFIG_PAD      = CONFIGURATION_NS + "pad"
## This is set to control how properties are stored:
## relative - a properties file is created relative to each URN (default)
## combined - All properties are lumped into the same file in the volume (more efficient)
CONFIG_PROPERTIES_STYLE = CONFIGURATION_NS + "property_style"

#/** These are standard aff4 attributes */
AFF4_STORED     =NAMESPACE +"stored"
AFF4_TYPE       =NAMESPACE +"type"
AFF4_INTERFACE  =NAMESPACE +"interface"
AFF4_CONTAINS   =NAMESPACE +"contains"
AFF4_SIZE       =NAMESPACE +"size"
AFF4_SHA        =NAMESPACE +"sha256"
AFF4_TIMESTAMP  =NAMESPACE +"timestamp"

## Supported interfaces
AFF4_STREAM     =NAMESPACE +"stream"
AFF4_VOLUME     =NAMESPACE +"volume"

#/** ZipFile attributes */
AFF4_VOLATILE_HEADER_OFFSET   = VOLATILE_NS + "relative_offset_local_header"
AFF4_VOLATILE_COMPRESSED_SIZE = VOLATILE_NS + "compress_size"
AFF4_VOLATILE_CRC             = VOLATILE_NS + "crc32"
AFF4_VOLATILE_COMPRESSION     = VOLATILE_NS + "compression"
AFF4_VOLATILE_FILE_OFFSET     = VOLATILE_NS + "file_offset"
AFF4_VOLATILE_DIRTY           = VOLATILE_NS + "dirty"

## Volume attributes
AFF4_IDENTITY_STORED = NAMESPACE + "identity" ## Indicates an identity
                                              ## is stored in this
                                              ## volume

AFF4_AUTOLOAD = NAMESPACE +"autoload" ## A hint that this stream
                                      ## should be automatically
                                      ## loaded as a volume

#/** Image attributes */
AFF4_CHUNK_SIZE =NAMESPACE + "chunk_size"
AFF4_COMPRESSION =NAMESPACE + "compression"
AFF4_CHUNKS_IN_SEGMENT =NAMESPACE + "chunks_in_segment"
AFF4_DIRECTORY_OFFSET =VOLATILE_NS + "directory_offset"

#/** Link, encryption attributes */
AFF4_TARGET= NAMESPACE + "target"

#/** Map attributes */
AFF4_BLOCKSIZE= NAMESPACE + "blocksize"
AFF4_IMAGE_PERIOD= NAMESPACE + "image_period"
AFF4_TARGET_PERIOD= NAMESPACE + "target_period"
AFF4_MAP_DATA =   NAMESPACE + "map_data"

#/* Identity attributes */
AFF4_STATEMENT        = NAMESPACE   + "statement"
AFF4_CERT             = NAMESPACE   + "x509"
AFF4_PRIV_KEY         = VOLATILE_NS + "priv_key"
AFF4_COMMON_NAME      = NAMESPACE   + "common_name"
AFF4_IDENTITY_PREFIX  = FQN         + "identity"
AFF4_HASH_TYPE        = FQN         + "hash_type"

## A property indicating this object should be highlighted
AFF4_HIGHLIGHT        = NAMESPACE   + "highlight"  

## Encrypted stream attributes
#// Thats the passphrase that will be used to encrypt the session key
AFF4_VOLATILE_PASSPHRASE = VOLATILE_NS + "passphrase"

## This is the master key for encryption (Never written down)
AFF4_VOLATILE_KEY               = VOLATILE_NS + "key"

AFF4_CRYPTO_NAMESPACE           = NAMESPACE + "crypto:"

## The intermediate key is obtained from pbkdf2() of the
## passphrase and salt. Iteration count is the fortification.
AFF4_CRYPTO_FORTIFICATION_COUNT = AFF4_CRYPTO_NAMESPACE + "fortification"
AFF4_CRYPTO_IV       = AFF4_CRYPTO_NAMESPACE + "iv"
AFF4_CRYPTO_RSA      = AFF4_CRYPTO_NAMESPACE + "rsa"

## This is the image master key encrypted using the intermediate key
AFF4_CRYPTO_PASSPHRASE_KEY      = AFF4_CRYPTO_NAMESPACE + "passphrase_key"
AFF4_CRYPTO_ALGORITHM           = AFF4_CRYPTO_NAMESPACE + "algorithm"
AFF4_CRYPTO_BLOCKSIZE           = AFF4_CRYPTO_NAMESPACE + "blocksize"
## The nonce is the salt encrypted using the image master key. Its
## used to check the master key is correct:
AFF4_CRYPTO_NONCE               = AFF4_CRYPTO_NAMESPACE + "nonce"

#// Supported algorithms
AFF4_CRYPTO_ALGORITHM_AES_SHA254 = "AES256/SHA256"

#/** These are standard aff4 types */
# Volumes:
AFF4_RAW_VOLUME       ="raw_volume"
AFF4_RAW_STREAM       ="raw_stream"
AFF4_ZIP_VOLUME       ="zip_volume"
AFF4_DIRECTORY_VOLUME ="directory"
AFF4_EWF_VOLUME       ="ewf_volume"
AFF4_EWF_STREAM       ="ewf_stream"
AFF4_AFF1_VOLUME       ="aff1_volume"
AFF4_AFF1_STREAM       ="aff1_stream"

# Streams:
AFF4_SEGMENT          ="segment"
AFF4_LINK             ="link"
AFF4_IMAGE            ="image"
AFF4_MAP              ="map"
AFF4_ENCRYTED         ="encrypted"
AFF4_ERROR_STREAM     ="error"

# misc:
AFF4_IDENTITY         ="identity"

## The following URNs are special and should be known by the
## implementation:
AFF4_SPECIAL_URN_NULL = FQN + "null" ## This URN refers to NULL data
                                     ## in Sparse maps (unread data
                                     ## not the same as zero)

AFF4_SPECIAL_URN_ZERO = FQN + "zero" ## This is used to represent long
                                     ## runs of zero

## Common properties of files and inodes
AFF4_MTIME = FQN + "mtime"
AFF4_ATIME = FQN + "atime"
AFF4_CTIME = FQN + "ctime"
AFF4_MODE  = FQN + "mode"

## Signals this object should inherit attributes from another object
AFF4_INHERIT = FQN + "inherit"

## PyFlag specific attributes
PYFLAG_NS = "urn:pyflag:"
PYFLAG_STREAM = PYFLAG_NS + "streams:"
PYFLAG_REVERSE_STREAM = PYFLAG_STREAM + "reverse"
