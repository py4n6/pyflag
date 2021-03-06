/*
** fs_types
** The Sleuth Kit 
**
** $Date: 2007/04/04 20:06:57 $
**
** Identify the type of file system being used
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/

#include "fs_tools_i.h"

/* Based on tsk_fs_open.c in TCT-1.07 */

typedef struct {
    char *name;
    TSK_FS_INFO_TYPE_ENUM code;
    char *comment;
} FS_TYPES;

/* The table used to parse input strings - supports
 * legacy strings - in order of expected usage
 */
FS_TYPES fs_open_table[] = {
    {"ntfs", TSK_FS_INFO_TYPE_NTFS_AUTO, "NTFS"},
    {"fat", TSK_FS_INFO_TYPE_FAT_AUTO, "auto-detect FAT"},
    {"ext", TSK_FS_INFO_TYPE_EXT_AUTO, "Ext2/Ext3"},
    {"iso9660", TSK_FS_INFO_TYPE_ISO9660, "ISO9660 CD"},
//    {"hfs", HFS, "HFS+"},
    {"ufs", TSK_FS_INFO_TYPE_FFS_AUTO, "UFS 1 & 2"},
    {"raw", TSK_FS_INFO_TYPE_RAW, "Raw Data"},
    {"swap", TSK_FS_INFO_TYPE_SWAP, "Swap Space"},
    {"fat12", TSK_FS_INFO_TYPE_FAT_12, "TSK_FS_INFO_TYPE_FAT_12"},
    {"fat16", TSK_FS_INFO_TYPE_FAT_16, "TSK_FS_INFO_TYPE_FAT_16"},
    {"fat32", TSK_FS_INFO_TYPE_FAT_32, "TSK_FS_INFO_TYPE_FAT_32"},
    {"linux-ext", TSK_FS_INFO_TYPE_EXT_AUTO, "auto-detect Linux EXTxFS"},
    {"linux-ext2", TSK_FS_INFO_TYPE_EXT_2, "Linux TSK_FS_INFO_TYPE_EXT_2"},
    {"linux-ext3", TSK_FS_INFO_TYPE_EXT_3, "Linux TSK_FS_INFO_TYPE_EXT_3"},
    {"bsdi", TSK_FS_INFO_TYPE_FFS_1, "BSDi FFS"},
    {"freebsd", TSK_FS_INFO_TYPE_FFS_1, "FreeBSD FFS"},
    {"netbsd", TSK_FS_INFO_TYPE_FFS_1, "NetBSD FFS"},
    {"openbsd", TSK_FS_INFO_TYPE_FFS_1, "OpenBSD FFS"},
    {"solaris", TSK_FS_INFO_TYPE_FFS_1B, "Solaris FFS"},
    {0},
};

/* Used to print the name given the code */
FS_TYPES fs_test_table[] = {
    {"ntfs", TSK_FS_INFO_TYPE_NTFS_AUTO, ""},
    {"fat", TSK_FS_INFO_TYPE_FAT_AUTO, ""},
    {"ext", TSK_FS_INFO_TYPE_EXT_AUTO, ""},
    {"ufs", TSK_FS_INFO_TYPE_FFS_AUTO, ""},
//    {"hfs", HFS, ""},
    {"iso9660", TSK_FS_INFO_TYPE_ISO9660, ""},
    {"raw", TSK_FS_INFO_TYPE_RAW, ""},
    {"swap", TSK_FS_INFO_TYPE_SWAP, ""},
    {"fat12", TSK_FS_INFO_TYPE_FAT_12, ""},
    {"fat16", TSK_FS_INFO_TYPE_FAT_16, ""},
    {"fat32", TSK_FS_INFO_TYPE_FAT_32, ""},
    {"linux-ext2", TSK_FS_INFO_TYPE_EXT_2, ""},
    {"linux-ext3", TSK_FS_INFO_TYPE_EXT_3, ""},
    {"ufs", TSK_FS_INFO_TYPE_FFS_1, ""},
    {"ufs", TSK_FS_INFO_TYPE_FFS_1B, ""},
    {"ufs", TSK_FS_INFO_TYPE_FFS_2, ""},
    {0},
};

FS_TYPES fs_usage_table[] = {
    {"ext", 0, "Ext2/Ext3"},
    {"fat", 0, "TSK_FS_INFO_TYPE_FAT_12/16/32"},
    {"ntfs", 0, "NTFS"},
    //{"hfs", 0, "HFS+"},
    {"iso9660", 0, "ISO9660 CD"},
    {"ufs", 0, "UFS 1 & 2"},
    {"raw", 0, "Raw Data"},
    {"swap", 0, "Swap Space"},
    {0},
};


TSK_FS_INFO_TYPE_ENUM
tsk_fs_parse_type(const TSK_TCHAR * str)
{
    FS_TYPES *sp;
    char tmp[16];
    int i;

    // convert to char
    for (i = 0; i < 15 && str[i] != '\0'; i++) {
        tmp[i] = (char) str[i];
    }
    tmp[i] = '\0';

    for (sp = fs_open_table; sp->name; sp++) {
        if (strcmp(tmp, sp->name) == 0) {
            return sp->code;
        }
    }
    return TSK_FS_INFO_TYPE_UNSUPP;
}


/* Used by the usage functions to display supported types */
void
tsk_fs_print_types(FILE * hFile)
{
    FS_TYPES *sp;
    tsk_fprintf(hFile, "Supported file system types:\n");
    for (sp = fs_usage_table; sp->name; sp++)
        tsk_fprintf(hFile, "\t%s (%s)\n", sp->name, sp->comment);
}

char *
tsk_fs_get_type(TSK_FS_INFO_TYPE_ENUM ftype)
{
    FS_TYPES *sp;
    for (sp = fs_test_table; sp->name; sp++)
        if (sp->code == ftype)
            return sp->name;

    return NULL;
}
