#!/usr/bin/env python
# vim: tabstop=4 softtabstop=4 shiftwidth=4 noexpandtab
#
# Program that patches Dell PowerEdge BMC firmware files.
# It allows to adjust hardcoded fan thresholds so that
# fans can be swapped with other aftermarket models (e.g.
# silent ones.
#
# Arnuschky, 2011
# http://projects.nuschkys.net/projects/dell-poweredge-2800/
#
import sys
import os
import re
from collections import namedtuple
from struct import *

# check python version
if sys.version_info < (2,6,0):
	sys.stderr.write("You need python 2.6 or later to run this script\n")
	exit(1)

# header of the container file size
FILE_HEADER_SIZE = 17
# header for each subfile block size
BLOCK_HEADER_SIZE = 51
# sensor block header size
SENSOR_INFO_HEADER_SIZE = 5
# fan sensor data size (+string)
FAN_SENSOR_INFO_DATA_SIZE = 43
# magic multiplier as in IPMI spec
IMPI_VALUE_MULTIPLIER = 75

# CRC (plain)  table 
# thanks to pycrc! http://www.tty1.net/pycrc/index_en.html
CRC16_TABLE = [
		0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
		0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
		0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
		0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
		0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
		0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
		0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
		0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
		0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
		0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
		0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
		0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
		0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
		0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
		0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
		0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
		0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
		0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
		0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
		0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
		0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
		0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
		0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
		0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
		0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
		0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
		0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
		0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
		0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
		0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
		0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
		0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
]

# CRC (XModem) table
# thanks to pycrc! http://www.tty1.net/pycrc/index_en.html
CRC16_XMODEM_TABLE = [
      0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
      0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
      0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
      0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
      0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
      0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
      0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
      0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
      0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
      0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
      0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
      0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
      0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
      0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
      0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
      0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
      0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
      0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
      0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
      0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
      0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
      0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
      0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
      0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
      0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
      0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
      0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
      0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
      0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
      0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
      0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
      0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
]

# mapping between system codes and display name
# Note: these seem to be cities
systems = dict()
systems['BB']		= 'PowerEdge 2850'
#systems['BRCL']	= 'unknown PowerEdge'
systems['BRLN']	= 'PowerEdge 1950'
systems['BULN']	= 'PowerEdge 2900 (Gen III)'
systems['CAL']	= 'PowerEdge R300'
#systems['CAT']	= 'unknown PowerEdge'
#systems['DEF']	= 'unknown PowerEdge'
#systems['EXPE']	= 'unknown PowerEdge'
#systems['FT']	= 'unknown PowerEdge'
#systems['FTT']	= 'unknown PowerEdge'
#systems['GL']	= 'unknown PowerEdge'
#systems['GNS']	= 'unknown PowerEdge'
#systems['GUAD']	= 'unknown PowerEdge'
#systems['HEL']	= 'unknown PowerEdge'
systems['K_C']		= 'PowerEdge 2800'
systems['LOND']		= 'PowerEdge 2950'
#systems['MC']	= 'unknown PowerEdge'
systems['MEC']	= 'PowerEdge 1900 (Gen I)'
#systems['MEL']	= 'unknown PowerEdge'
#systems['MIR']	= 'unknown PowerEdge'
systems['MNTRL']	= 'PowerEdge 2900'
systems['MUS']	= 'PowerEdge 1800'
systems['NAG']	= 'Poweredge SC1425'
#systems['OSLO']	= 'unknown PowerEdge'
#systems['SEO']	= 'unknown PowerEdge'
#systems['SF']	= 'unknown PowerEdge'
systems['STL']	= 'PowerEdge 840'
#systems['VANG']	= 'unknown PowerEdge'
#systems['VESO']	= 'unknown PowerEdge'



###########################
# Structure of the main container file header
#
class FileHeader():
	def __init__(self, unpackdata):
		self.hex02         = unpackdata[0]
		self.numBlocks     = unpackdata[1]
		self.filesize      = unpackdata[2]
		self.zero          = unpackdata[3]
		self.dellHeaderStr = unpackdata[4]

	def __str__(self):
		return "File header: numBlocks=%d filesize=%d dellHeaderStr='%s'" % (self.numBlocks, self.filesize, self.dellHeaderStr) 


###########################
# Structure of a block header (subfile definition)
#
class BlockHeader():
	def __init__(self, unpackdata):
		self.zero1         = unpackdata[0]
		self.btype         = unpackdata[1]
		self.zero2         = unpackdata[2]
		self.systemId      = unpackdata[3]
		self.zero3         = unpackdata[4]
		self.zero4         = unpackdata[5]
		self.zero5         = unpackdata[6]
		self.unknownFixed  = unpackdata[7]
		self.crc16         = unpackdata[8]
		self.length        = unpackdata[9]
		self.offset        = unpackdata[10]
		self.filename      = unpackdata[11]

	def __str__(self):
		return "Block header: type=%d systemId=%d crc=0x%04x length=%d offset=%d filename='%s'" % (self.btype, self.systemId, self.crc16, self.length, self.offset, self.filename) 


###########################
# Structure of a header for each sensor info block
#
class SensorInfoHeader():
	def __init__(self, unpackdata):
		self.blockId = unpackdata[0]
		self.tag0051 = unpackdata[1]
		self.sclass  = unpackdata[2]
		self.length  = unpackdata[3]


###########################
# Structure of a fan sensor info block
#
class FanSensorInfoBlock():
	def __init__(self, unpackdata):
		self.fill2000      = unpackdata[0]
		self.sensorId      = unpackdata[1]
		self.unknown1      = unpackdata[2]
		self.threshold     = unpackdata[3]
		self.unknown2      = unpackdata[4]
		self.fill05050000  = unpackdata[5]
		self.thingy        = unpackdata[6]
		self.name          = unpackdata[7]


###########################
# Object that holds the firmware file info
# (header and filename)
#
class Firmware:
	def __init__(self):
		self.ffile = None
		self.header = None


###########################
# Object defining everything we know about the 
# PowerEdge system we want to patch
#
class PowerEdgeSystem:
	def __init__(self):
		self.idStr = ""
		self.sensorBlockId = 0
		self.sensorBlockHeader = None
		self.numFans = 0
		self.fanNames = list()
		self.fanThresholds = list()
		self.fanSpeeds = list()
		self.sensorNumbers = list()
		self.unknown = False


########################################################
# computes CRC-16 (plain)
# used in main container file (last two bytes)
# and once for each subfile (stored in the header)
# @return crc 16bit
#
def crc16(data, crc):
	for byte in data:
		crc = (crc >> 8) ^ CRC16_TABLE[(crc ^ ord(byte)) & 0xff]
	return crc


########################################################
# Computes CRC-16 (Xmodem)
# Used for each sensor info block (last two bytes of block)
# @return crc 16bit
#
def crc16xmodem(data, crc):
	for byte in data:
		crc = ((crc << 8) & 0xffff) ^ CRC16_XMODEM_TABLE[((crc >> 8) ^ ord(byte)) & 0xff]
	return crc


########################################################
# Checks that the main container file is valid.
# Checks filesize, CRC, header string/structure.
# Simply bails out if CRC does not match.
#
def verifyFile(firmwareFile):
	print "Verifying file..."
	# read file header
	firmwareFile.seek(0, os.SEEK_SET)
	fileHeaderData = firmwareFile.read(FILE_HEADER_SIZE)
	fileHeader = FileHeader(unpack('<BBLH9s', fileHeaderData))

	# get filesize
	firmwareFile.seek(0, os.SEEK_END)
	filesize = firmwareFile.tell()

	# check that size matches, and all other data is as expected
	if (fileHeader.hex02 != 2 or fileHeader.zero != 0 or fileHeader.filesize != filesize or fileHeader.dellHeaderStr in 'DELL_INC'):
		sys.stderr.write("Error: invalid/unexpected file header found!\n")
		sys.exit(1)

	# read the whole file and compare the computed CRC16 against the one stored at the end of the file
	firmwareFile.seek(0, os.SEEK_SET)
	fileData = firmwareFile.read(filesize - 2)
	fileCRC16 = unpack("<H", firmwareFile.read(2))[0]
	computedCRC16 = crc16(fileData, 0)
	if (fileCRC16 != computedCRC16):
		sys.stderr.write("Error: file CRC failed (0x%04x vs. 0x%04x)!\n" % (fileCRC16, computedCRC16))
		sys.exit(1)

	firmwareFile.seek(0, os.SEEK_SET)


########################################################
# Verify a given sensor block by reading the header,
# reading the data from the file and compute the CRC for it.
# Then compare the CRC recorded in the header with the computed one.
# Simply bails out if CRC does not match.
#
def verifyBlock(firmware, blockId):
	print "Verifying sensor block..."

	# reading block header
	firmware.ffile.seek(FILE_HEADER_SIZE + blockId * BLOCK_HEADER_SIZE, os.SEEK_SET)
	blockHeaderData = firmware.ffile.read(BLOCK_HEADER_SIZE)
	blockHeader = BlockHeader(unpack('<BBBB3BHHLL32s', blockHeaderData))

	# check that data is as expected
	if (blockHeader.zero1 != 0 or blockHeader.zero2 != 0 or blockHeader.zero3 != 0 or blockHeader.zero4 != 0 or blockHeader.zero5 != 0):
		sys.stderr.write("Error: invalid/unexpected block header found!\n")
		sys.exit(1)

	# compute the CRC16 of the block and compare to value recorded in headed
	firmware.ffile.seek(blockHeader.offset, os.SEEK_SET)
	blockData = firmware.ffile.read(blockHeader.length)
	computedCRC16 = crc16(blockData, 0)
	if (blockHeader.crc16 != computedCRC16):
		sys.stderr.write("Error: block type %d systemId %d CRC failed (0x%04x vs. 0x%04x)!\n" % (blockHeader.btype, blockHeader.systemId, blockHeader.crc16, computedCRC16))
		sys.exit(1)


########################################################
# Reads the firmware header and stores it together
# with the file object in a structure.
# @return Firmware object
#
def readFirmwareHeader(firmwareFile):
	firmware = Firmware()
	firmware.ffile = firmwareFile

	# read file header
	firmware.ffile.seek(0, os.SEEK_SET)
	fileHeaderData = firmware.ffile.read(FILE_HEADER_SIZE)
	firmware.header = FileHeader(unpack('<BBLH9s', fileHeaderData))

	return firmware


########################################################
# Scans the firmware for available systems.
# A system is defined by a set of tables, all named as
# follows <TABLE>_<SYSTEM>.FLC. Tables types are unknown
# as are most systems. SD_K_C.FLC is the sensor info
# table for a PowerEdge 2800.
# @param Firmware object
# @return list of PowerEdge objects found
#
def scanSystems(firmware):
	print "Scanning firmware file for available systems"

	# read header and store it
	print " - reading and parsing file header"
	firmware.ffile.seek(0, os.SEEK_SET)
	fileHeaderData = firmware.ffile.read(FILE_HEADER_SIZE)
	fileHeader = FileHeader(unpack('<BBLH9s', fileHeaderData))

	peSystems = list()
	firmware.ffile.seek(FILE_HEADER_SIZE, os.SEEK_SET)
	for blockId in range(fileHeader.numBlocks):
		print "Reading block header #%d" % blockId
		firmware.ffile.seek(FILE_HEADER_SIZE + blockId * BLOCK_HEADER_SIZE, os.SEEK_SET)
		blockHeaderData = firmware.ffile.read(BLOCK_HEADER_SIZE)
		blockHeader = BlockHeader(unpack('<BBBB3BHHLL32s', blockHeaderData))
		print " - verifying block header and block data integrity CRC16"
		verifyBlock(firmware, blockId)
		print " - %s" % blockHeader

		print " - checking for sensor block..."
		if (blockHeader.systemId > 0 and blockHeader.btype == 11):
			print "    > found sensor block!"
			m = re.match('^SD_(.*)\.FLC', blockHeader.filename)
			if (m):
				peSystem = PowerEdgeSystem()
				peSystem.sensorBlockId = blockId
				peSystem.sensorBlockHeader = blockHeader
				if (m.group(1) in systems):
					peSystem.unknown = False
					peSystem.idStr = systems[m.group(1)]
					print "    > found a known system: %s" % peSystem.idStr
				else:
					peSystem.unknown = True
					peSystem.idStr = "unknown PowerEdge (code: %s)" % m.group(1)
					print "    > found an unknown system."
	
				peSystem = scanSensorBlock(firmware, peSystem)
				peSystems.append(peSystem)

	return peSystems


########################################################
# Scans the sensor table for fans and stores the retrieved
# info (number of fans, RPMs etc) in the PowerEdge object
# @param Firmware object
# @param PowerEdge object (selected system)
#
def scanSensorBlock(firmware, peSystem):
	firmware.ffile.seek(peSystem.sensorBlockHeader.offset, os.SEEK_SET)
	numInfos = unpack('<B', firmware.ffile.read(1))[0]
	whatever = unpack('<B', firmware.ffile.read(1))[0]
	if (numInfos + whatever != 0x100):
		print "Error: Invalid sensor block start header"
		sys.exit(1)
	
	print "Sensor info block with %d sensors, whatever is 0x%02x" % (numInfos, whatever)
		
	# scan all the sensor blocks
	infoIdx=0
	while (infoIdx < numInfos):
		#firmware.ffile.tell() < (peSystem.sensorBlockHeader.offset + peSystem.sensorBlockHeader.length)):
		# read sensor info header to check if we might have a fan block
		sensorInfoHeaderData = firmware.ffile.read(SENSOR_INFO_HEADER_SIZE)
		sensorInfoHeader = SensorInfoHeader(unpack('<BHBB', sensorInfoHeaderData))
		print " Sensor info header blockId %d class %d length %d" % (sensorInfoHeader.blockId, sensorInfoHeader.sclass, sensorInfoHeader.length)
		# quit if we've reached the padding
		if (sensorInfoHeader.tag0051 == 0xffff):
			break

		# make sure we know what we're talking about
		if (sensorInfoHeader.tag0051 != 0x5100):
			print "Error: Invalid sensorInfoHeader.tag0051 %04x" % sensorInfoHeader.tag0051
			sys.exit(1)
		print " -> CRC ok"

		# read the sensor info data
		sensorInfoData = firmware.ffile.read(sensorInfoHeader.length)
		sensorInfoDataCRC16 = unpack('<H', firmware.ffile.read(2))[0]
		computedCRC16 = crc16xmodem(sensorInfoHeaderData+sensorInfoData, 0)

		if (sensorInfoDataCRC16 != computedCRC16):
			sys.stderr.write("Error: sensor info blockId %d CRC failed (0x%04x vs. 0x%04x)!\n" % (sensorInfoHeader.blockId, sensorInfoDataCRC16, computedCRC16))
			sys.exit(1)

		# try to find out if we have a fan sensor block, if yes parse it!
		if (sensorInfoHeader.sclass == 1):
			fanSensorInfoBlock = FanSensorInfoBlock(unpack('<HB32sBBLH%ds' % (sensorInfoHeader.length - FAN_SENSOR_INFO_DATA_SIZE), sensorInfoData))
			print "Class 1 info block sensor id %d" % fanSensorInfoBlock.sensorId
			if (fanSensorInfoBlock.fill2000 == 0x0020 and fanSensorInfoBlock.fill05050000 == 0x00000505):
				fanSpeedThreshold = fanSensorInfoBlock.threshold * IMPI_VALUE_MULTIPLIER
				print " --> found valid fan sensor info block: %s: %d/%d RPM" % (fanSensorInfoBlock.name, fanSensorInfoBlock.threshold, fanSpeedThreshold)
				peSystem.numFans += 1
				peSystem.fanNames.append(fanSensorInfoBlock.name)
				peSystem.fanThresholds.append(fanSensorInfoBlock.threshold)
				peSystem.fanSpeeds.append(fanSpeedThreshold)
				peSystem.sensorNumbers.append(fanSensorInfoBlock.sensorId)

		infoIdx += 1

	return peSystem


########################################################
# Write the fan sensor info from the PowerEdge object back into
# the firmware file.
# @param Firmware object
# @param PowerEdge object (selected system)
#
def writeSensorBlock(firmware, peSystem):
	firmware.ffile.seek(peSystem.sensorBlockHeader.offset, os.SEEK_SET)
	numInfos = unpack('<B', firmware.ffile.read(1))[0]
	whatever = unpack('<B', firmware.ffile.read(1))[0]
	if (numInfos + whatever != 0x100):
		print "Error: Invalid sensor block start header"
		sys.exit(1)
	
	# scan all the sensor blocks
	infoIdx=0
	while (infoIdx < numInfos):
		#firmware.ffile.tell() < (peSystem.sensorBlockHeader.offset + peSystem.sensorBlockHeader.length)):
		# read sensor info header to check if we might have a fan block
		sensorInfoHeaderData = firmware.ffile.read(SENSOR_INFO_HEADER_SIZE)
		sensorInfoHeader = SensorInfoHeader(unpack('<BHBB', sensorInfoHeaderData))
		print " Sensor info header blockId %d class %d length %d" % (sensorInfoHeader.blockId, sensorInfoHeader.sclass, sensorInfoHeader.length)
		# quit if we've reached the padding
		if (sensorInfoHeader.tag0051 == 0xffff):
			break

		# make sure we know what we're talking about
		if (sensorInfoHeader.tag0051 != 0x5100):
			print "Error: Invalid sensorInfoHeader.tag0051 %04x" % sensorInfoHeader.tag0051
			sys.exit(1)
		print " -> CRC ok"

		# read the sensor info data
		sensorInfoData = firmware.ffile.read(sensorInfoHeader.length)
		sensorInfoDataCRC16 = unpack('<H', firmware.ffile.read(2))[0]
		computedCRC16 = crc16xmodem(sensorInfoHeaderData+sensorInfoData, 0)

		if (sensorInfoDataCRC16 != computedCRC16):
			sys.stderr.write("Error: sensor info blockId %d CRC failed (0x%04x vs. 0x%04x)!\n" % (sensorInfoHeader.blockId, sensorInfoDataCRC16, computedCRC16))
			sys.exit(1)

		# try to find out if we have a fan sensor block, if yes parse it!
		if (sensorInfoHeader.sclass == 1):
			fanSensorInfoBlock = FanSensorInfoBlock(unpack('<HB32sBBLH%ds' % (sensorInfoHeader.length - FAN_SENSOR_INFO_DATA_SIZE), sensorInfoData))
			#print "Class 1 info block sensor id %d" % fanSensorInfoBlock.sensorId
			if (fanSensorInfoBlock.fill2000 == 0x0020 and fanSensorInfoBlock.fill05050000 == 0x00000505):
				fanSpeedThreshold = fanSensorInfoBlock.threshold * IMPI_VALUE_MULTIPLIER
				print " found valid fan sensor info block: %s: %d/%d RPM" % (fanSensorInfoBlock.name, fanSensorInfoBlock.threshold, fanSpeedThreshold)
				fanIndex = peSystem.sensorNumbers.index(fanSensorInfoBlock.sensorId)
				if (fanSensorInfoBlock.threshold != peSystem.fanThresholds[fanIndex]):
					fanSensorInfoBlock.threshold = peSystem.fanThresholds[fanIndex]
					print "  --> updating fan sensor with new threshold %d" % fanSensorInfoBlock.threshold
					firmware.ffile.seek(-(sensorInfoHeader.length+2), os.SEEK_CUR)
					sensorInfoData = pack('<HB32sBBLH%ds' % (sensorInfoHeader.length - FAN_SENSOR_INFO_DATA_SIZE), fanSensorInfoBlock.fill2000, fanSensorInfoBlock.sensorId, fanSensorInfoBlock.unknown1, fanSensorInfoBlock.threshold, fanSensorInfoBlock.unknown2, fanSensorInfoBlock.fill05050000, fanSensorInfoBlock.thingy, fanSensorInfoBlock.name)
					firmware.ffile.write(sensorInfoData)

					# write the sensor block CRC
					computedCRC16 = crc16xmodem(sensorInfoHeaderData+sensorInfoData, 0)
					print "  --> computing and updating sensor block CRC 0x%04x" % computedCRC16
					firmware.ffile.write(pack("<H", computedCRC16))

		infoIdx += 1


########################################################
#
# @param Firmware object
# @param PowerEdge object (selected system)
# @param PowerEdge object
# @param PowerEdge object
#
def updateBlockCRC(firmware, peSystem):
	firmware.ffile.seek(peSystem.sensorBlockHeader.offset, os.SEEK_SET)
	blockData = firmware.ffile.read(peSystem.sensorBlockHeader.length)
	peSystem.sensorBlockHeader.crc16 = crc16(blockData, 0)
	print "Writing sensor CRC 0x%04x" % peSystem.sensorBlockHeader.crc16
	firmware.ffile.seek(FILE_HEADER_SIZE + peSystem.sensorBlockId * BLOCK_HEADER_SIZE, os.SEEK_SET)
	firmware.ffile.write(pack('<BBBB3BHHLL32s', peSystem.sensorBlockHeader.zero1, peSystem.sensorBlockHeader.btype, peSystem.sensorBlockHeader.zero2, peSystem.sensorBlockHeader.systemId, peSystem.sensorBlockHeader.zero3, peSystem.sensorBlockHeader.zero4, peSystem.sensorBlockHeader.zero5, peSystem.sensorBlockHeader.unknownFixed, peSystem.sensorBlockHeader.crc16, peSystem.sensorBlockHeader.length, peSystem.sensorBlockHeader.offset, peSystem.sensorBlockHeader.filename))


########################################################
# Update the total CRC (plain CRC16), covers all data, stored in
# last two bytes of firmware files
# @param Firmware object
# @param PowerEdge object (selected system)
#
def updateFileCRC(firmware, peSystem):
	# get filesize
	firmware.ffile.seek(0, os.SEEK_END)
	filesize = firmware.ffile.tell()

	firmware.ffile.seek(0, os.SEEK_SET)
	fileData = firmware.ffile.read(filesize - 2)
	computedCRC16 = crc16(fileData, 0)
	print "Writing file CRC 0x%04x" % computedCRC16
	firmware.ffile.write(pack("<H", computedCRC16))

	

###############################################################################
#
# Main
#
###############################################################################

# check command line arguments and open file
if (len(sys.argv) != 2):
	sys.stderr.write("Usage: %s <firmware>\n" % sys.argv[0])
	sys.exit(1)

print "Opening file '%s'" % sys.argv[1]
firmwareFile = open(sys.argv[1], "r+")

# read firmware header
firmware = readFirmwareHeader(firmwareFile)
# verify the file before we do anything
verifyFile(firmwareFile)
# read the data file and scan for available pe systems
peSystems = scanSystems(firmware)

#
# Present found data to user and let hir select the system to patch
#
print "\nSystems found in firmware file:\n"
for i in range(len(peSystems)):
	peSystem = peSystems[i]
	print " %2d) %s" % (i+1, peSystem.idStr)
	print "     Number of fans: %d" % (peSystem.numFans)
	print "     Fan names     : %s" % (', '.join(peSystem.fanNames))
	print "     Fan speeds    : %s" % (str(peSystem.fanSpeeds).strip('[]'))
	print "     Sensor numbers: %s" % (str(peSystem.sensorNumbers).strip('[]'))
	print
i += 1

num = 0
while (num <= 0 or num > i):
	sys.stdout.write("Select (1-%d): " % i)
	try:
		num = int(raw_input())
	except ValueError:
		print "Oops!  That was no valid number.  Try again..."

peSystem = peSystems[num-1]
print "You selected the following system: %s\n" % (peSystem.idStr)

print "  Number of fans: %d" % (peSystem.numFans)
print "  Fan names     : %s" % (', '.join(peSystem.fanNames))
print "  Fan speeds    : %s" % (str(peSystem.fanSpeeds).strip('[]'))
print "  Sensor numbers: %s" % (str(peSystem.sensorNumbers).strip('[]'))
print

#
# Present all fan sensors for the selected system and let hir
# select sensor to change, write file or bail out
#
while (type(num) is not str):
	print "Select fan to adjust:\n"
	for i in range(peSystem.numFans):
		print " %2d) fan sensor number %2d, threshold %4d, name '%s'" % (i+1, peSystem.sensorNumbers[i], peSystem.fanSpeeds[i], peSystem.fanNames[i])
	print
	print "  w) write sensor thresholds to firmware"
	print "  x) quit without any changes"
	print
	i += 1
	num = 0
	while (num <= 0 or num > i):
		sys.stdout.write("Select (1-%d,w): " % i)
		num = raw_input()
		if (num.lower() == 'w' or num.lower() == 'x'):
			break;

		try:
			num = int(num)
		except ValueError:
			print "Oops!  That was no valid number.  Try again..."

	if (type(num) is str):
		break;

	num -= 1
	print
	print "Editing threshold for fan number %d (%s)" % (peSystem.sensorNumbers[num], peSystem.fanNames[num]) 
	print "Value will be multipled with %d to give actual RPM value" % IMPI_VALUE_MULTIPLIER
	print "Current value is %d (= %d RPM)" % (peSystem.fanThresholds[num], peSystem.fanSpeeds[num])
	print "Enter new value: "
	value = -1
	while (value < 0 or value > 255):
		sys.stdout.write("Select (0-255): ")
		try:
			value = int(raw_input())
		except ValueError:
			print "Oops!  That was no valid number.  Try again..."
	peSystem.fanThresholds[num] = value
	peSystem.fanSpeeds[num] = value * IMPI_VALUE_MULTIPLIER

if (type(num) is not str or num.lower() == 'x'):
	sys.exit(1)

# write block
writeSensorBlock(firmware, peSystem)
# recompute CRC update header
updateBlockCRC(firmware, peSystem)
# recompute total CRC update header
updateFileCRC(firmware, peSystem)
# verify block
verifyBlock(firmware, peSystem.sensorBlockId)
# verify file
verifyFile(firmwareFile)

print 
print "All done."
print
print "**Disclaimer **"
print 
print "If you flash this firmware, you might render your PowerEdge server unusable."
print "It might even be unrecoverable. Additionally, badly set thresholds might cause"
print "overheating."
print
print "I am not responsible for any damage that is done to your system."
print
print "                      YOU HAVE BEEN WARNED!"
print
print "Nevertheless, this patch worked fine for me."
print "If it does work for you as well, please leave some feedback:"
print "http://projects.nuschkys.net/projects/dell-poweredge-2800/"
print
if (peSystem.unknown):
	print "Please also report this string '"+peSystem.idStr+"'"
	print "along with your type of PowerEdge! Thank you."
	print
sys.exit(0)

