#!/usr/bin/env python
# -*- coding: latin-1 -*-
#█▀▀▀▀█▀▀▀▀▀██▀▀▀▀██▀▀▀▀▀▀ ▀▀▀▀▀▀▀▀▀▀▀▓▒▀▀▀▀▀▀▀▀▀▀█▓▀ ▀▀▀██▀▀▀▀▀▀▀▀▀▓▓▀▀▀▀▀▀▀▀▀▌
#▌▄██▌ ▄▓██▄ ▀▄█▓▄▐ ▄▓█▓▓▀█ ▄▓██▀▓██▓▄ ▌▄█▓█▀███▓▄ ▌▄█▓█ ▀ ▄▓██▀▓██▓▄ ▄█▓█▀███▄■
#▌▀▓█▓▐▓██▓▓█ ▐▓█▓▌▐▓███▌■ ▒▓██▌ ▓██▓▌▐▓▒█▌▄ ▓██▓▌ ▐▓▒█▌▐ ▒▓██▌  ▓██▓▌▓▒█▌ ▓█▓▌
#▐▓▄▄▌░▓▓█▓▐▓▌ █▓▓▌░▓▓█▓▄▄ ▓▓██▓▄▄▓█▓▓▌░▓█▓ █ ▓█▓▓▌░▓█▓ ▒ ▓▓██▓▄▄▓█▓▓▌▓█▓ ░ ▓█▓▓
#▐▓▓█▌▓▓▓█▌ █▓▐██▓▌▐▓▒▓▌ ▄ ▐░▓█▌▄ ▀▀▀ ▐▓▓▓ ▐▌ ▀▀▀  ▐▓▓▓▄▄ ▐░▓█▌ ▄ ▀▀▀ ▓▓▓ ░ ██▓▓
#▐▓▓▓█▐▓▒██ ██▓▓▓▌▐▓▓██  █▌▐▓▓▒▌▐ ███░▌▐▓▓▒▌▐ ███░▌ ▐▓▓▒▌ ▐▓▓▒▌▀ ███░▌▓▓▒▌ ███░
# ▒▓▓█▌▒▓▓█▌ ▐▓█▒▒  ▒▓██▌▐█ ▒▓▓█ ▐█▓▒▒ ▒▒▓█  ▐█▓▒▒  ▒▒▓█ ▓▌▒▓▓█ ▐█▓▒▒ ▒▒▓█ ▐█▓▒▌
#▌ ▒▒░▀ ▓▒▓▀  ▀░▒▓ ▐▌ ▓▓▓▀ █ █▒▓▀▀░█▓ ▄▌ ▒▒▓▀▀░█▓ ▄▌ ▒▒▓▀▀ █▒▓▀▀░█▓ ▒▒▓▀▀░█▀
#█▄ ▀ ▄▄ ▀▄▄▀■ ▀ ▀▓█▄ ▀ ▄█▓█▄ ▀ ▓▄▄▄▄▄█▀ ▄▀ ▄▄▄▄▄▄█▓▄ ▀ ▄▄█▓▄▀ ▄▓▄█▄▀ ▄▄▄█▌
#
# Copyright (C) 2017 Jonathan Racicot
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http:#www.gnu.org/licenses/>.
# </copyright>
# <author>Jonathan Racicot</author>
# <email>infectedpacket@gmail.com</email>
# <date>2017-01-01/date>
# <url>https://github.com/infectedpacket</url>
# <summary>
#  This program will decompress Parrot firmware files for the
#  Parrot SkyController and possibly other PLF files as well, as they
#  appear to be a standard format across Parrot drones firmware.
#
#  Todo:
#    - Figure out CRC32 checks and apply them
#	 - Figure out the 2 Uint following the flags
#	 - Create symbolic links/files
# </summary>
# Further Reading
#
# Racicot, J., Reversing the Parrot SkyController Firmware, Infected Packets, http://wp.me/p852om-8Q  
# (accessed #on 2017-01-09)
#//////////////////////////////////////////////////////////////////////////////
#
#//////////////////////////////////////////////////////////////////////////////
# Program Information
#
PROGRAM_NAME = "vulture"
PROGRAM_DESC = "Extracts information and contents from a Parrot firmware file."
PROGRAM_USAGE = "%(prog)s -r <firmware> -o <output> [-t] [-v]"
#
#//////////////////////////////////////////////////////////////////////////////
# Imports Statements
#
import os
import sys
import json
import zlib
import base64
import struct
import binascii
import argparse
import traceback
from logger import *
#
#//////////////////////////////////////////////////////////////////////////////
# Argument Parser Declaration
#
usage = PROGRAM_USAGE
parser = argparse.ArgumentParser(
	usage=usage, 
	prog=PROGRAM_NAME, 
	description=PROGRAM_DESC)
io_options=parser.add_argument_group("I/O Options", "Input and output data options.")
io_options.add_argument("-r", "--read", 
	dest="input", 
	required=True,
	help="Parrot firmware file to read.")
io_options.add_argument("-o", "--output", 
	dest="output", 
	default=os.getcwd(),
	help="Output directory into which files will be extracted to.")	
io_options.add_argument("-v", "--verbose", 
	dest="verbose", 
	action="store_true",
	default=False,
	help="Display additional information about decompression process.")	
io_options.add_argument("-t", "--test", 
	dest="test", 
	action="store_true",
	help="Do not extract files. Only list them and output JSON data about its contents.")	
#//////////////////////////////////////////////////////////////////////////////
# Globals and Constants
#	
PLF_MAGIC = b'PLF!'

ERR_INVALID_FIRMWARE = "Invalid Parrot firmware file: {magic:s}."
ERR_FAILED_CRC_CHECK = "Entry CRC32 integrity check failed for entry."
ERR_EXPECTED_CRC	= "Expecting 0x{e_crc:08x}, got 0x{d_crc:08x}."
ERR_LINK_CREATE		= "Could not create link: {error:s}."
ERR_NO_INSTALL_DATA	= "No install file found in firmware."

INFO_CREATED_DIR	= "Created directory '{dir:s}'."
INFO_CREATED_FILE	= "Created file '{file:s}' ({nbbytes:d} byte(s))."
INFO_CREATED_LINK	= "Linked file '{file:s}' to '{link:s}'."
INFO_FILE_DATA		= "{file:s}: {size:d} byte(s)."
INFO_NB_ENTRIES		= "{nbentries:d} entries found in '{firmware:s}'."
INFO_NB_PARTITIONS	= "{nbentries:d} partition(s) found in '{firmware:s}'."

WARN_UNKNOWN_ENTRY	= "Unknown entry type: 0x{type:02x}."

P_HDR_VER		=	"header_version"
P_HDR_SIZE		=	"header_size"
P_HDR_ENTRY_SIZE= 	"entry_header_size"
P_HDR_F_VMAJ	=	"firm_version_major"
P_HDR_F_VMIN	=	"firm_version_minor"
P_HDR_F_VREV	=	"firm_version_revision"
P_HDR_FILE_SIZE	=	"file_size"
P_INSTALL_PLF	=	"install_file_path"
P_BOOTLDR_FILE	=	"bootloader_file_path"
P_PERMS		=	"permissions"
P_FILENAME 	= 	"filename"
P_SYMLINK	=	"symlink"
P_DATA		=	"data"
P_DATA_CRC	=	"data_crc"
P_DIRNAME 	= 	"dir_name"
P_FILETYPE	=	"file_type"
P_UNCOMPRESS=	"uncompressed_size"
P_ENTRY_TYPE=	"entry_type"
P_CALC_CRC32=	"crc32"
P_INST_PLF	=	"install_file"
P_PART_TBL_V=	"partition_tbl_vers"
P_PART_VERS =	"partition_vers	"
P_NB_PART	=	"nb_partitions"

ENTRY_000			= 0x00
ENTRY_003			= 0x03
ENTRY_008			= 0x08
ENTRY_FILESYSTEM 	= 0x09
ENTRY_BOOT			= 0x07
ENTRY_CONFIG		= 0x0B
ENTRY_INSTALL		= 0x0C

FS_DIR				= 0x04
FS_FILE				= 0x08
FS_LINK				= 0x0A

VOL_TYPE_RAW		= 0x00	#no file system is available on this device
VOL_TYPE_STATIC		= 0x01	#filesystem is available but will not change (e.g. for the boot partitions)
VOL_TYPE_DYNAMIC	= 0x02  #A filesystem is available and can be changed 

#
#//////////////////////////////////////////////////////////////////////////////
# Core functions
#
class FirmwareFile(object):
	'''
	Represents a firmware file for Parrot devices.
	
	The FirmwareFile object includes a set of methods and variables to
	manipulate Parrot firmware file and extract contents from it.
	
	@version 1.0
	@date 2016-12-25
	'''
	def __init__(self, _file, _logger=None):
		'''
		Creates and parse a new Parrot firmware file.
		
		@param _file Firmware file
		@param _logger For debugger and information purposes.
		'''
		if (_logger == None): self.logger = Logger(sys.stdin)
		else: self.logger = _logger	
		
		self.firmware = _file
		self.install_file = None
		self.bootloader_file = None
		self.unknown_plf = None
		self.properties = {}
		self.partitions = []
		self._parse()
		
	def _parse(self):
		'''
		Parses the firmware file into configuration information and file system
		data for extraction.
		
		This function will first parse the firmware header to extract relevant
		information and then read each entry of the firmware file.
		'''
		with open(self.firmware, "rb") as f:
			self._read_header(f)
			self._extract_entries(f)
						
	def is_valid_parrot_file(self, _magic):
		'''
		Checks if the firmware file is a Parrot firmware.
		
		@param _magic Magic bytes read from the file
		@return Tru if magic bytes matches expected "PLF!"
		'''
		return _magic == PLF_MAGIC
		
	def _u16(self, _bytes):
		'''
		Reads an unsigned short from the given bytes.
		
		@param _bytes Bytes to convert
		@return Unsigned short from the bytes.
		'''
		return struct.unpack("H", _bytes)[0]
	
	def _u32(self, _bytes):
		'''
		Reads an unsigned integer from the given bytes.
		
		@param _bytes Bytes to convert
		@return Unsigned integer from the bytes.
		'''	
		return struct.unpack("I", _bytes)[0]
	
	def _read_ushort(self, _fhandle):
		'''
		Reads an unsigned short (2 bytes) from the given stream
		
		@param _fhandle Stream to read
		@return Unsigned short read from the stream.
		'''	
		return self._u16(_fhandle.read(2))
	
	def _read_uint(self, _fhandle):
		'''
		Reads an unsigned integer (4 bytes) from the given stream
		
		@param _fhandle Stream to read
		@return Unsigned integer read from the stream.
		'''		
		return self._u32(_fhandle.read(4))
	
	def _read_chars(self, _fhandle, _len, _filter=[]):
		'''
		Reads a given number of characters from the given stream
		
		@param _fhandle Stream to read
		@param _len Number of characters to read.
		@return String read from the stream.
		'''		
		string = ""
		for i in range(0, _len):
			byte = ord(_fhandle.read(1))
			if (byte not in _filter):
				string += chr(byte)
		return string
	
	def _read_string(self, _fhandle):
		'''
		Reads a string from the given stream.
		
		This function will read characters from the stream until a null byte
		is read. The characters read will be converted into a string.
		
		@param _fhandle Stream to read
		@return String read from the stream.
		'''		
		string = ""
		byte = ord(_fhandle.read(1))
		while (byte != 0):
			string += chr(byte)
			byte = ord(_fhandle.read(1))
		return string

	def _read_header(self, _fhandle):
		'''
		Read the firmware header and parses the extracted information into the
		FirwmareFile object.
		
		The structure of the Parrot firmware file header is as follow:
		
			typedef struct sPLFFile
			{
			  u32 dwMagic; 
			  u32 dwHdrVersion;
			  u32 dwHeaderSize;
			  u32 dwEntryHeaderSize;
			  u32 uk_0x10;
			  u32 uk_0x14;
			  u32 uk_0x18;
			  u32 uk_0x1C;
			  u32 uk_0x20;
			  u32 dwVersionMajor;
			  u32 dwVersionMinor;
			  u32 dwVersionBugfix;
			  u32 uk_0x30;
			  u32 dwFileSize;
			}
		
		Reference:
		https://embedded-software.blogspot.ca/2010/12/plf-file-format.html
		
		@param _fhandle Stream of the firmware file.
		'''
		self.magic = struct.unpack("4s", _fhandle.read(4))[0]
		if (not self.is_valid_parrot_file(self.magic)):
			raise Exception(ERR_INVALID_FIRMWARE.format(magic=self.magic))
		
		self.properties[P_HDR_VER] 			= self._read_uint(_fhandle)
		self.properties[P_HDR_SIZE]			= self._read_uint(_fhandle)
		self.properties[P_HDR_ENTRY_SIZE]	= self._read_uint(_fhandle)
		self.properties["hdr_unknown_10"] 	= self._read_uint(_fhandle)
		self.properties["hdr_unknown_14"] 	= self._read_uint(_fhandle)
		self.properties["hdr_unknown_18"] 	= self._read_uint(_fhandle)
		self.properties["hdr_unknown_1C"] 	= self._read_uint(_fhandle)
		self.properties["hdr_unknown_20"] 	= self._read_uint(_fhandle) # Maybe checksum
		self.properties[P_HDR_F_VMAJ] 		= self._read_uint(_fhandle)
		self.properties[P_HDR_F_VMIN] 		= self._read_uint(_fhandle)
		self.properties[P_HDR_F_VREV] 		= self._read_uint(_fhandle)
		self.properties["hdr_unknown_30"] 	= self._read_uint(_fhandle)
		self.properties[P_HDR_FILE_SIZE] 	= self._read_uint(_fhandle)
		
	def _extract_entries(self, _fhandle):
		'''
		Extract all entries from the firmware file and returns them
		into an array.
		
		@param _fhandle Stream of the firmware file.
		@return Array of FirmwareEntry objects.
		'''
		self.entries = []

		while (_fhandle.tell() < self.properties[P_HDR_FILE_SIZE]):
			new_entry = self._extract_entry(_fhandle)
			self.entries.append(new_entry)
		
	def _extract_entry(self, _fhandle):
		'''
		Extract the entry at the current cursor position within the given
		file stream. Returns a FirmwareEntry object containing the extracted
		information.
		
		@param _fhandle Stream of the firmware file.
		@return A FirmwareEntry object
		'''
		entry_start = _fhandle.tell()
		entry_type = self._read_uint(_fhandle)
		entry_size = self._read_uint(_fhandle)
		entry_crc  = self._read_uint(_fhandle)
		entry_unk1 = self._read_uint(_fhandle)
		entry_usize= self._read_uint(_fhandle)
		f_entry = FirmwareEntry(entry_start, entry_type, entry_size, entry_crc)
		f_entry.properties[P_ENTRY_TYPE] = entry_type
		f_entry.properties[P_UNCOMPRESS] = entry_usize

		if (entry_type == ENTRY_FILESYSTEM):
			self._extract_filesystem_elem(_fhandle, f_entry)
		elif (entry_type == ENTRY_BOOT):
			self._extract_bootloader_elem(_fhandle, f_entry)
		elif (entry_type == ENTRY_003):
			self._extract_03_elem(_fhandle, f_entry)
		elif (entry_type == ENTRY_CONFIG):
			self._extract_config_elem(_fhandle, f_entry)
		elif (entry_type == ENTRY_INSTALL):
			self._extract_install_elem(_fhandle, f_entry)
		else:
			self.logger.print_warning(WARN_UNKNOWN_ENTRY.format(type=entry_type))
			_fhandle.read(entry_size)
			
		# Read/burn padding bytes
		if (entry_size % 4 != 0):
			padding = ((entry_size//4)+1)*4 - entry_size
			_fhandle.read(padding)

		return f_entry
		
	def _extract_filesystem_elem(self, _fhandle, _fentry):
		'''
		Retuns a FileSystemElement object containing the file system
		data read from the firmware.
		
		@param _fhandle Stream of the firmware file.
		@param _fentry Updated FirmwareEntry object.
		'''
		fs_elem = None
		fs_elem_name = ""
		fs_elem_data = None
		is_compressed = (_fentry.properties[P_UNCOMPRESS] > 0)
		
		if (not is_compressed):
			fs_elem_name = self._read_string(_fhandle)
		
			flags = self._read_uint(_fhandle)
			unk04 = self._read_uint(_fhandle)
			unk08 = self._read_uint(_fhandle)
			
			(permissions, file_type) = self._get_file_properties(flags)
			_fentry.properties[P_FILETYPE] = file_type
			_fentry.properties[P_PERMS] = oct(permissions)
			
			if (file_type == FS_DIR):
				_fentry.properties[P_DIRNAME] = fs_elem_name
			elif (file_type == FS_FILE):
				fs_elem_data = _fhandle.read(_fentry.size-len(fs_elem_name)-13)
				fs_elem_crc  = binascii.crc32(fs_elem_data)
				_fentry.properties[P_FILENAME] 	= fs_elem_name
				_fentry.properties[P_DATA] 		= fs_elem_data
			elif (file_type == FS_LINK):
				fs_elem_data = self._read_string(_fhandle)
				_fentry.properties[P_FILENAME] 	= fs_elem_name
				_fentry.properties[P_SYMLINK] 	= fs_elem_data
		else:
			fcontents = _fhandle.read(_fentry.size)
			(fs_elem_name, fs_flags, fs_elem_data) = self._uncompress_file(fcontents)
			(permissions, file_type) = self._get_file_properties(fs_flags)
			_fentry.properties[P_FILENAME] = fs_elem_name
			_fentry.properties[P_DATA] = fs_elem_data
			_fentry.properties[P_FILETYPE] = file_type
			_fentry.properties[P_PERMS] = permissions 
	
	def _get_file_properties(self, _flags):
		'''
		Returns the permissions and type based on the given flags.
		
		@param _flags 32-bit integer containing the file properties
		@return Tuple containing the permissions and file type in the format
			(permissions, file_type)
		'''
		fperm = _flags & 0x0FFF
		ftype = (_flags & 0xF000) >> 12
		return (fperm, ftype)
		
	def _uncompress_file(self, _data):
		'''
		Uncompresses a GZip-compressed file found within a Parrot firmware file.
		
		This function accepts a chunk of GZip-compressed data from a firmware file
		and returns the name of the file compressed with its uncompressed data.
		
		@param _data Compressed data.
		@return (filename, uncompressed contents)
		'''
		fname = ""
		cdata = _data
		udata = zlib.decompress(cdata, 15 + 32)
		data = udata.split(b'\x00', 1)
		fname = data[0]
		udata = data[1]
		flags = self._u32(bytes(udata[0:4]))	
		unk2 = self._u32(bytes(udata[4:8]))
		unk3 = self._u32(bytes(udata[8:12]))
		return (fname, flags, udata[12:])
		
	def _extract_config_elem(self, _fhandle, _fentry):
		'''
		Retuns a ConfigurationEkement object containing the configuration
		data read from the firmware.
		
		typedef struct sPartitionSectionTag
		{
		  u32 dwTblVersion;
		  u32 dwVersionMajor;
		  u32 dwVersionMinor;
		  u32 dwVersionBugfix;
		  u32 uk_0x10;
		  u32 uk_0x14;
		  u32 uk_0x18;
		  u32 uk_0x1C;
		  u32 uk_0x20;
		  u32 dwNumEntries;
		}
		
		@param _fhandle Stream of the firmware file.
		@param _fentry Updated FirmwareEntry object.
		'''	
		cfg_tbl_version 	= self._read_uint(_fhandle)
		cfg_v_major 		= self._read_uint(_fhandle)
		cfg_v_minor			= self._read_uint(_fhandle)
		cfg_v_rev			= self._read_uint(_fhandle)
		unk1				= self._read_uint(_fhandle)
		unk2				= self._read_uint(_fhandle)
		unk3				= self._read_uint(_fhandle)
		unk4				= self._read_uint(_fhandle)
		unk5				= self._read_uint(_fhandle)
		cfg_nb_entries		= self._read_uint(_fhandle)
		
		self.properties[P_PART_TBL_V] = cfg_tbl_version
		self.properties[P_PART_VERS] = "{:d}.{:d}.{:d}".format(cfg_v_major, cfg_v_minor, cfg_v_rev)
		self.properties[P_NB_PART] = cfg_nb_entries
		
		
		for i in range(0, cfg_nb_entries):
			p_entry					= Partition()
			p_entry.device			= self._read_ushort(_fhandle)
			p_entry.volume_type		= self._read_ushort(_fhandle)
			p_entry.volume			= self._read_ushort(_fhandle)
			unk1					= self._read_ushort(_fhandle)
			p_entry.volume_size		= self._read_uint(_fhandle)
			p_entry.volume_action	= self._read_uint(_fhandle)
			p_entry.volume_name		= self._read_chars(_fhandle, 32, [0])
			p_entry.mount_name		= self._read_chars(_fhandle, 32, [0])
			self.partitions.append(p_entry)
			self.logger.print_debug(str(p_entry))
		
	def _extract_install_elem(self, _fhandle, _fentry):
		'''
		Extracts the installation file contained within the firmware
		file.
		
		@param _fhandle Stream of the firmware file.
		@param _fentry Updated FirmwareEntry object.		
		'''
		data = _fhandle.read(_fentry.size)
		self.install_file = data

	def _extract_bootloader_elem(self, _fhandle, _fentry):
		'''
		Extracts the bootloader file contained within the firmware
		file.
		
		@param _fhandle Stream of the firmware file.
		@param _fentry Updated FirmwareEntry object.		
		'''
		data = _fhandle.read(_fentry.size)
		self.bootloader_file = data
		
	def _extract_03_elem(self, _fhandle, _fentry):
		'''
		Extracts the PLF file in entry type 03 file contained 
		within the firmware file.
		
		@param _fhandle Stream of the firmware file.
		@param _fentry Updated FirmwareEntry object.		
		'''
		data = _fhandle.read(_fentry.size)
		self.unknown_plf = data		
		
	def save_install_file_to(self, _outputfile):
		'''
		Saves the installation file found within the firmware to the specified
		file.
		
		@param _outputfile Filename of the file to write to
		@exception Exception if no installation data found.
		'''
		if (self.install_file):
			with open(_outputfile, "wb+") as f:
				f.write(self.install_file)
			self.properties[P_INSTALL_PLF] = _outputfile
		
	def save_boot_file_to(self, _outputfile):
		'''
		Saves the bootloader file found within the firmware to the specified
		file.
		
		@param _outputfile Filename of the file to write to
		@exception Exception if no installation data found.
		'''
		if (self.bootloader_file):
			with open(_outputfile, "wb+") as f:
				f.write(self.bootloader_file)	
			self.properties[P_BOOTLDR_FILE] = _outputfile
		
	def save_entry03_file_to(self, _outputfile):
		'''
		Saves the bootloader file found within the firmware to the specified
		file.
		
		@param _outputfile Filename of the file to write to
		@exception Exception if no installation data found.
		'''
		if (self.unknown_plf):
			with open(_outputfile, "wb+") as f:
				f.write(self.unknown_plf)		
			self.properties["entry03_file_path"] = _outputfile
		
	def get_filesystem_entries(self):
		'''
		Returns a list of all entries relating to the file system of
		the device.
		
		@return A list of FirmwareEntry objects linked to the file system.
		'''
		fs_entries = []
		for entry in self.entries:
			if entry.is_filesystem():
				fs_entries.append(entry)
		return fs_entries
		
	def extract_files_to(self, _output, _test=True):
		'''
		Will write directories and files contained within the firmware to the
		specified directory.
		
		@param _output Directory to write the files to.
		'''
		fs_entries = self.get_filesystem_entries()
		for fs_entry in fs_entries:
			if (fs_entry.is_directory()):
				dir_name = fs_entry.properties[P_DIRNAME]
				dir_name = os.path.join(_output, dir_name)
				if ("win" in sys.platform.lower()):
					dir_name = dir_name.replace("/", os.sep)
					
				if (not (_test or os.path.isdir(dir_name)) ):
					os.makedirs(dir_name)
				self.logger.print_success(dir_name)
				
			elif (fs_entry.is_file()):
				file_name = fs_entry.properties[P_FILENAME]
				file_name = os.path.join(_output, file_name)
				if ("win" in sys.platform.lower()):
					file_name = file_name.replace("/", os.sep)
		
				file_contents = fs_entry.properties[P_DATA]
				if (not _test):
					with open(file_name, "wb") as f:
						f.write(file_contents)
				self.logger.print_success(INFO_FILE_DATA.format(
					file=file_name, 
					size=len(file_contents)))
					
			elif (fs_entry.is_symlink()):
				file_name = fs_entry.properties[P_FILENAME]
				linked_file = fs_entry.properties[P_SYMLINK]
				
				file_name = os.path.join(_output, file_name)
				linked_file = os.path.join(_output, linked_file)
				
				if ("win" in sys.platform.lower()):
					file_name = file_name.replace("/", os.sep)
					linked_file = linked_file.replace("/", os.sep)
				
				if (not _test):
					try:
						os.symlink(linked_file, file_name)
					except Exception as e:
						self.logger.print_debug(ERR_LINK_CREATE.format(error=str(e)))
				
				self.logger.print_success(file_name)
			
	def save_meta_to_json(self, _output):
		'''
		Saves metadata about the contents of the firmware into
		the specified file using the JSON format.
		
		@param _output JSON output file
		'''

		with open(_output, "w") as f:
			json_dict = self.properties
			json_dict["file"] = self.firmware
			
			if (P_INSTALL_PLF in self.properties):
				json_dict[P_INSTALL_PLF] = self.properties[P_INSTALL_PLF]
			if (P_BOOTLDR_FILE in self.properties):
				json_dict[P_BOOTLDR_FILE] = self.properties[P_BOOTLDR_FILE]

			json.dump(json_dict, fp=f, indent=4)
			json.dump({"entries" : self.entries}, 
				fp=f,
				default=self.entry_to_json,
				indent=4)
			json.dump({"partitions" : self.partitions}, 
				fp=f, 
				default=self.partition_to_json,
				indent=4)
			
	def entry_to_json(self, _entry):
		'''
		Serialize the firmware entry object into a JSON string.
		
		@return JSON string of the firmware entry
		'''
		json_dict = {}
		json_dict["entry_offset"] 	= _entry.offset
		json_dict["entry_type"] 	= _entry.type
		json_dict["entry_size"] 	= _entry.size
		json_dict["entry_crc32"]	= _entry.crc32
		json_dict.update(_entry.properties)
		
		
		if P_INST_PLF in json_dict:
			del json_dict[P_INST_PLF]

		if P_DATA in json_dict:
			del json_dict[P_DATA]
			
		return json_dict			
		
	def partition_to_json(self, _partition):
		'''
		Serialize the firmware entry object into a JSON string.
		
		@return JSON string of the firmware entry
		'''
		json_dict = {}
		json_dict["p_device"] 		= _partition.device
		json_dict["p_volume_type"] 	= _partition.volume_type
		json_dict["p_volume"] 		= _partition.volume
		json_dict["p_volume_size"] 	= _partition.volume_size
		json_dict["volume_action"] 	= _partition.volume_action
		json_dict["volume_name"] 	= _partition.volume_name
		json_dict["mount_name"]		= _partition.mount_name
		
		return json_dict		
		
class FirmwareEntry(object):
	'''
	Contains data about a single firmware entry within the firmware
	file.
	'''
	def __init__(self, _offset, _type, _size, _crc32):
		self.offset = _offset
		self.type = _type
		self.size = _size
		self.crc32 = _crc32
		self.properties = {}	#Contains properties, values about the object within
								#the entry.

	def is_filesystem(self):
		'''
		Specifies if the current entry relates to the file system of the device.
		
		@return True if the firmware entry relates to the file system.
		'''
		return P_FILETYPE in self.properties and self.properties[P_ENTRY_TYPE] == ENTRY_FILESYSTEM
		
	def is_directory(self):
		'''
		Specifies if the current entry is directory information.
		
		@return True if the firmware entry relates to a directory.
		'''
		if (self.is_filesystem()):
			return P_FILETYPE in self.properties and self.properties[P_FILETYPE] == FS_DIR
		return False
		
	def is_file(self):
		'''
		Specifies if the current entry is file information.
		
		@return True if the firmware entry relates to a file.
		'''	
		if (self.is_filesystem()):
			return P_FILETYPE in self.properties and self.properties[P_FILETYPE] == FS_FILE
		return False		

	def is_symlink(self):
		'''
		Specifies if the current entry is symbolic link information.
		
		@return True if the firmware entry relates to a symbolic link.
		'''	
		if (self.is_filesystem()):
			return P_FILETYPE in self.properties and self.properties[P_FILETYPE] == FS_LINK
		return False
		
		
class Partition(object):
	'''
	Describes a partition as found within the "Configuration Entry" within 
	a Parrot firmware file.
	'''
	def __init__(self, _device=0x0, _volume_type=0x0, _volume=0x0,
		_volume_size=0x0, _volume_action=0x0, _volume_name="",
		_mount_name=""):
		
		self.device 		= _device
		self.volume_type	= _volume_type
		self.volume			= _volume
		self.volume_size 	= _volume_size
		self.volume_action 	= _volume_action
		self.volume_name	= _volume_name
		self.mount_name		= _mount_name
		
	def __str__(self):
		fmt = "Mount: {mname:s}, Device: 0x{dev:04x}, Volume:[Name: {vname:s}, Type: {vtype:04x}, ID: {vid:04x}, Size: {vsize:d}, Action: {vact:08x}]"
		data = fmt.format(
			dev=self.device,
			vtype=self.volume_type,
			vid=self.volume,
			vsize=self.volume_size,
			vact=self.volume_action,
			vname=self.volume_name,
			mname=self.mount_name)
		return data
		
#
#//////////////////////////////////////////////////////////////////////////////
# Main
#

def main(_args):
	try:
		# Modify as needed
		install_filename = "install.plf"
		boot_filename = "boot.bin"
		entry03_filename = "entry03.plf"
		meta_filename = "meta.json"
		
		# Shouldn't need to change anything below
		# unless new feature.
		file = _args.input
		output = _args.output
		is_test = _args.test
		is_verbose = _args.verbose
		

		logger = Logger(_output=sys.stdout)
		logger.debug = is_verbose
		
		firmware = FirmwareFile(file, logger)
		nb_entries = len(firmware.entries)
		nb_partitions = len(firmware.partitions)
		
		logger.print_info(INFO_NB_ENTRIES.format(
			nbentries=nb_entries,
			firmware=file))
		
		logger.print_info(INFO_NB_PARTITIONS.format(
			nbentries=nb_partitions,
			firmware=file))
		
		# If the output dir doesn't exists, create it
		if (not os.path.isdir(output)):
			os.makedirs(output)
		
		# Extracts files to the output directory
		firmware.extract_files_to(output, _test=is_test)
		
		# Saves the bootloading file to the specified file.
		bootloader_path = os.path.join(output, boot_filename)
		firmware.save_boot_file_to(bootloader_path)
		
		# Saves the install file to the specified file.
		install_path = os.path.join(output, install_filename)
		firmware.save_install_file_to(install_path)		
		
		# Saves the entry 03 file to the specified file.
		entry03_path = os.path.join(output, entry03_filename)
		firmware.save_entry03_file_to(entry03_path)
		
		# Saves information about the firmware into a JSON file
		meta_path = os.path.join(output, meta_filename)
		firmware.save_meta_to_json(meta_path)
		
	except Exception as e:
		print(str(e))
		traceback.print_exc()
#
#//////////////////////////////////////////////////////////////////////////////
# Launcher
#
if __name__ == "__main__":
	args = parser.parse_args()
	main(args)
#
#//////////////////////////////////////////////////////////////////////////////	
		
	