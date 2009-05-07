# Volatility
# Copyright (c) 2007,2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

"""
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

"""Tool: This tool generates a crash dump from a image of ram
"""
import os,optparse
import struct
from time import gmtime, strftime

from vutils import is_crash_dump
from thirdparty.progressbar import *
from forensics.object import *
from forensics.addrspace import FileAddressSpace
from forensics.win32.info import find_psactiveprocesshead
from forensics.win32.info import find_psloadedmodulelist
from forensics.win32.info import find_mmpfndatabase
from forensics.win32.info import find_kddebuggerdatablock
from forensics.win32.info import find_kddebuggerdatablock
from forensics.win32.info import find_systemtime
from forensics.win32.info import find_suitemask

from forensics.win32.tasks import process_list
from forensics.win32.tasks import process_addr_space
from forensics.win32.tasks import peb_number_processors
from forensics.win32.tasks import process_peb

#from forensics.win32.tasks import *

dump_hdr= ""
# 0x00
dump_hdr+="\x50\x41\x47\x45\x44\x55\x4D\x50\x0F\x00\x00\x00\x28\x0A\x00\x00"
# 0x10
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x20  
dump_hdr+="\x4C\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x30
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x50\x41\x47\x45"
# 0x40
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x50
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x00\x41\x47\x45"
# 0x60
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x70
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x80
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x90
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0xa0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0xb0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0xc0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0xd0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0xe0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0xf0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x100
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x110
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x120
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x130
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x140
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x150
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x160
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x170
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x180
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x190
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x1a0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x1b0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x1c0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x1d0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x1e0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x1f0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x200
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x210
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x220
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x230
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x240
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x250
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x260
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x270
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x280
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x290
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x2a0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x2b0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x2c0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x2d0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x2e0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x2f0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x300
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x310
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x320
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x330
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x340
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x350
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x360
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x370
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x380
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x390
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x3a0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x3b0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x3c0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x3d0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x3e0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x3f0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x400
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x410
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x420
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x430
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x440
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x450
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x460
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x470
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x480
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x490
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x4a0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x4b0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x4c0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x4d0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x4e0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x4f0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x500
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x510
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x520
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x530
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x540
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x550
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x560
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x570
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x580
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x590
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x5a0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x5b0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x5c0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x5d0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x5e0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x50\x41\x47\x45"
# 0x5f0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x600
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x610
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x620
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x630
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x640
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x650
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x660
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x670
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x680
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x690
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x6a0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x6b0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x6c0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x6d0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x6e0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x6F0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x700
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x710
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x720
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x730
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x740
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x750
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x760
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x770
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x780
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x790
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x7a0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x7b0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x7c0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x00\x41\x47\x45"
# 0x7d0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x7e0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x7f0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x800
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x810
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 0x820
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x830
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x840
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x850
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x860
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x870
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x880
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x890
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x8a0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x8b0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x8c0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x8d0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x8e0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x8f0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x900
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x910
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x920
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x930
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x940
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x950
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x960
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x970
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x980
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x990
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x9a0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x9b0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x9c0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x9d0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x9e0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0x9f0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xA00
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xA10
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xA20
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xA30
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xA40
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xA50
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xA60
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xA70
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xA80
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xA90
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xAa0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xAb0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xAc0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xAd0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xAe0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xAf0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xb00
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xb10
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xb20
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xb30
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xb40
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xb50
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xb60
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xb70
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xb80
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xb90
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xba0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xbb0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xbc0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xbd0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xbe0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xbf0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xc00
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xc10
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xc20
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xc30
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xc40
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xc50
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xc60
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xc70
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xc80
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xc90
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xca0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xcb0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xcc0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xcd0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xce0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xcf0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xd00
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xd10
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xd20
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xd30
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
#  0xd40
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xd50
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xd60
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xd70
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xd80
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xd90
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xda0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xdb0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xdc0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xdd0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xde0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xdf0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xe00
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xe10
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xe20
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xe30
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xe40
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xe50
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xe60
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xe70
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xe80
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xe90
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xea0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xeb0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xec0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xed0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xee0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xef0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
#0xf00
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
#0xf10
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
#0xf20
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
#0xf30
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
#0xf40 
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
#0xf50
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xf60
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xf70
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xf80 
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x01\x00\x00\x00\x50\x41\x47\x45"
# 0xF90 
dump_hdr+="\x50\x41\x47\x45\x01\x00\x00\x00\x10\x01\x00\x00\x00\x00\x00\x00"
# 0xFA0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x50\x41\x47\x45\x00\x41\x47\x45"
# 0xFB0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x00\x00\x00\x00\x00\x00\x00\x00"
# 0xFC0
dump_hdr+="\x00\x00\x00\x00\x00\x00\x00\x00\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xFD0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xFE0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"
# 0xFF0
dump_hdr+="\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45\x50\x41\x47\x45"

num_of_runs = 0x00000001
base_page = 0x00000000
pae_enabled = 0x01

def find_numberprocessors(addr_space, types):

    NumberOfProcessorsDict = dict()
    all_tasks = process_list(addr_space, types)

    for task in all_tasks:

        if not addr_space.is_valid_address(task):
            continue
        
        process_address_space = process_addr_space(addr_space, types, task, addr_space.base.fname)
        if process_address_space is None:
            continue
                            
        peb = process_peb(addr_space, types, task)

        try:
            if not process_address_space.is_valid_address(peb):
                continue
        except:
	    continue

        NumberOfProcessors = peb_number_processors(process_address_space, types, peb)
	if NumberOfProcessors in NumberOfProcessorsDict:
	    NumberOfProcessorsDict[NumberOfProcessors] +=1
        else:
	    NumberOfProcessorsDict[NumberOfProcessors] = 1

    MaxNumberOfProcessors =max([ (NumberOfProcessorsDict[x],x) for x in NumberOfProcessorsDict])[1]

    return MaxNumberOfProcessors

def write_char_phys(value,member_list,hdr,types):

    (offset, current_type) = get_obj_offset(types, member_list)
    new_hdr = hdr[:offset] + struct.pack('=B',value) + hdr[offset+1:]
    return new_hdr

def write_long_phys(value,member_list,hdr,types):

    (offset, current_type) = get_obj_offset(types, member_list) 
    new_hdr = hdr[:offset] + struct.pack('=L',value) + hdr[offset+4:]
    return new_hdr
    
def write_long_long_phys(value,member_list,hdr,types):

    (offset, current_type) = get_obj_offset(types, member_list) 
    new_hdr = hdr[:offset] + struct.pack('=Q',value) + hdr[offset+8:]
    return new_hdr

def dd_to_crash(addr_space, types, symbol_table, opts):

    outfile = opts.outfile
    filename = opts.filename

    DirectoryTableBaseValue = addr_space.pgd_vaddr

    PsActiveProcessHead = find_psactiveprocesshead(addr_space, types)

    PsLoadedModuleList = find_psloadedmodulelist(addr_space,types)

    MmPfnDatabase = find_mmpfndatabase(addr_space, types)
   
    KdDebuggerDataBlock = find_kddebuggerdatablock(addr_space, types)

    NumberOfProcessors = find_numberprocessors(addr_space, types)

    SuiteMask = find_suitemask(addr_space, types)

    SystemTime = find_systemtime(addr_space, types)

    num_pages = os.path.getsize(filename)/4096
    page_count = num_pages

    new_hdr = write_long_phys(DirectoryTableBaseValue,['_DMP_HEADER', 'DirectoryTableBase'],dump_hdr,types)
    new_hdr = write_long_phys(PsLoadedModuleList,['_DMP_HEADER', 'PsLoadedModuleList'],new_hdr,types)
    new_hdr = write_long_phys(PsActiveProcessHead,['_DMP_HEADER', 'PsActiveProcessHead'],new_hdr,types)
    new_hdr = write_long_phys(KdDebuggerDataBlock,['_DMP_HEADER', 'KdDebuggerDataBlock'],new_hdr,types)
    new_hdr = write_long_phys(NumberOfProcessors,['_DMP_HEADER', 'NumberProcessors'],new_hdr,types)
    new_hdr = write_long_phys(MmPfnDatabase,['_DMP_HEADER', 'PfnDataBase'],new_hdr,types)
    new_hdr = write_long_phys(SuiteMask,['_DMP_HEADER', 'SuiteMask'],new_hdr,types)
    new_hdr = write_long_long_phys(SystemTime,['_DMP_HEADER', 'SystemTime'],new_hdr,types)

    if addr_space.pae == True:
        new_hdr = write_char_phys(pae_enabled,['_DMP_HEADER', 'PaeEnabled'],new_hdr,types)

    new_hdr = new_hdr[:100] + struct.pack('=L',num_of_runs) +\
                             struct.pack('=L',num_pages) +\
			     struct.pack('=L',0x00000000)  +\
			     struct.pack('=L',num_pages) +\
                             new_hdr[116:]

    MI=open(outfile,'wb')
    MI.write("%s"%new_hdr)

    FILEOPEN = open(filename, 'rb')
 
    offset = 0
    end = os.path.getsize(filename)

    widgets = ['Convert: ', Percentage(), ' ', Bar(marker=RotatingMarker()),
                       ' ', ETA()]
    pbar = ProgressBar(widgets=widgets, maxval=end).start()

    while offset <= end:
        fdata = FILEOPEN.read(0x1000)
	if fdata == None:
	    break
	MI.write("%s"%fdata)
	pbar.update(offset)
	offset+=0x1000
	 
    pbar.finish()
    print

    FILEOPEN.close()
    MI.close()

    return 

def crash_numberofpages(address_space, types, vaddr):
    return read_obj(address_space, types,
         ['_DMP_HEADER', 'PhysicalMemoryBlockBuffer', 'NumberOfPages'], vaddr)

def crash_to_dd(addr_space, types, output_file):

    if is_crash_dump(addr_space.fname) == False:
        print "Error: Crash dump file required as input"
        return
        
    NumberOfPages = crash_numberofpages(addr_space, types, 0)

    out = open(output_file, "wb")

    NumberOfRuns = read_obj(addr_space, types,
        ['_DMP_HEADER', 'PhysicalMemoryBlockBuffer', 'NumberOfRuns'], 0)
   

    run_base = ['_DMP_HEADER', 'PhysicalMemoryBlockBuffer', 'Run']

    widgets = ['Convert: ', Percentage(), ' ', Bar(marker=RotatingMarker()),
                       ' ', ETA()]
    pbar = ProgressBar(widgets=widgets, maxval=NumberOfPages).start()
    pages_written = 0

    current_file_page = 0x1000
    for i in xrange(NumberOfRuns):
        BasePage  = read_obj(addr_space, types, run_base + [i, 'BasePage'], 0)
        PageCount = read_obj(addr_space, types, run_base + [i, 'PageCount'], 0)
        out.seek(BasePage * 0x1000)
        for j in xrange(0, PageCount*0x1000, 0x1000):
            data = addr_space.read(current_file_page + j, 0x1000)
            out.write(data)
            pbar.update(pages_written)
            pages_written += 1
        current_file_page += (PageCount * 0x1000)
    pbar.finish()
    print
    out.close()

    return
