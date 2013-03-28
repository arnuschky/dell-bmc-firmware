// vim: ts=4 ai noexpandtab nopaste
/**
 * This program can extract and check the different files contained in a firmware file
 * for a Dell PowerEdge BMC.
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

typedef struct 
{
	uint8_t		hex02;
	uint8_t		numBlocks;	// number of subfiles in system
	uint32_t	filesize;
	uint16_t	zero;
	char		dellHeaderStr[9];
} header_t;

typedef struct
{
	uint8_t	    zero1;
	uint8_t	    type;	    // 0x000b -> SD_${system}.FLC
	uint8_t 	zero2;
	uint8_t 	system; 	// 0, 1, 2
	uint8_t		zeros[3];
  	uint16_t	unknownFixedData;
	uint16_t	crc16;
	uint32_t	length;
	uint32_t	offset;
	char		filename[32];
} flc_block_t;
// 4x1+3x1+2+2+4+4+32=51

uint16_t endian_swap16(uint16_t x)
{
	return (x>>8) | 
           (x<<8);
}

uint32_t endian_swap32(uint32_t x)
{
	return (x>>24) | 
	        ((x<<8) & 0x00FF0000) |
	        ((x>>8) & 0x0000FF00) |
	        (x<<24);
}

/** CRC table for the CRC-16. The poly is 0x8005 (x^16 + x^15 + x^2 + 1) */
uint16_t const crc16_table[256] = {
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
};

static inline uint16_t crc16_byte(uint16_t crc, const uint8_t data)
{
    return (crc >> 8) ^ crc16_table[(crc ^ data) & 0xff];
}

uint16_t calccrc16(uint8_t const *buffer, size_t len)
{
    uint16_t crc = 0x0000;

    while (len--)
        crc = crc16_byte(crc, *buffer++);
    return crc;
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <firmware>\n", argv[0]);
        exit(1);
    }
	FILE* flashFile = fopen(argv[1], "r");
	
    // get filesize
    fseek(flashFile, 0, SEEK_END);
    uint32_t filesize = ftell(flashFile);
    fseek(flashFile, 0, SEEK_SET);

	// read the header
	header_t header;
	if (fread(&header, sizeof(header_t), 1, flashFile) == 0)
    {
		fprintf(stderr, "Error: Can't read header.\n");
		exit(1);
    }

	// check that it's a valid header as far as we know
	if (header.hex02 != 0x02 ||
		header.zero != 0 ||
        filesize != header.filesize ||
		strncmp(header.dellHeaderStr, "DELL_INC", 8) != 0)
	{
		fprintf(stderr, "Error: Header not valid.\n");
		exit(1);
	}

    // calculate header crc
    fseek(flashFile, 0, 0);
    uint16_t totalHeaderSize = sizeof(flc_block_t) * header.numBlocks + sizeof(header_t);
    uint8_t headerBuf[totalHeaderSize];
    fread(&headerBuf, totalHeaderSize, 1, flashFile);
    uint16_t headerCRC16 = calccrc16(headerBuf, totalHeaderSize);

    // calculate total file crc
    fseek(flashFile, 0, 0);
    uint8_t fileBuf[header.filesize-2];
    fread(&fileBuf, header.filesize-2, 1, flashFile);
    uint16_t fileCRC16 = calccrc16(fileBuf, header.filesize-2);
    uint16_t fileCRC16Dell;
    fread(&fileCRC16Dell, 2, 1, flashFile);
    printf("\n\n");
	printf("Valid Dell PowerEdge BMC firmware header found:\n\n");
	printf("  - number of blocks : %d\n",	header.numBlocks);
	printf("  - oemstr (fixed)   : %s\n",	header.dellHeaderStr);
	printf("  - total file size  : %d\n",	header.filesize);
	printf("  - total header size: %d\n",	totalHeaderSize);
	printf("  - header CRC16     : 0x%04x\n",	headerCRC16);
	printf("  - total file CRC16 : 0x%04x\n\n",	fileCRC16);
    if (fileCRC16 == fileCRC16Dell)
       printf("  * CRC16 check OK\n");
    else
       printf("  * CRC16 check FAILED, actual CRC16 is 0x%04x instead of 0x%04x\n", fileCRC16, fileCRC16Dell);

    printf("\n\n");

	// read all blocks
    fseek(flashFile, sizeof(header_t), 0); 
	flc_block_t flcBlock[header.numBlocks];
	fread(&flcBlock, sizeof(flc_block_t), header.numBlocks, flashFile);

	uint8_t i;
	for (i = 0; i < header.numBlocks; i++)
	{
		// check if our understanding of format is correct
		if (flcBlock[i].zero1 != 0 || flcBlock[i].zero2 != 0 || flcBlock[i].zeros[0] != 0 ||
            flcBlock[i].zeros[1] != 0 || flcBlock[i].zeros[2] != 0)
		{
			fprintf(stderr, "Error: Block %d not valid.\n", i);
			exit(1);
		}

		printf("Block %d:\n\n", i);
		printf("  - type     : %d/0x%02x (defines block type, 0x0b is sensor data table)\n", flcBlock[i].type, flcBlock[i].type);
		printf("  - system # : %d/0x%02x (running number for systems in this firmware file)\n", flcBlock[i].system, flcBlock[i].system);
		printf("  - unknown  : %d/0x%04x (always same for all blocks in a single firmware file)\n", flcBlock[i].unknownFixedData, flcBlock[i].unknownFixedData);
		printf("  - offset   : %d\n", flcBlock[i].offset);
		printf("  - length   : %d\n", flcBlock[i].length);
		printf("  - filename : %s\n\n", flcBlock[i].filename);

		// extract the block according to the offset and length given in the block desc.
		printf("  * extracting block...");
		char* blockData = (char*) malloc(flcBlock[i].length);
		
		fseek(flashFile, flcBlock[i].offset, 0);
		fread(blockData, flcBlock[i].length, 1, flashFile);

		FILE* blockFile = fopen(flcBlock[i].filename, "w");
		fwrite(blockData, flcBlock[i].length, 1, blockFile);
        uint16_t blockCRC16 = calccrc16(blockData, flcBlock[i].length);
		fclose(blockFile);
		free(blockData);
		printf("done.\n");

        if (blockCRC16 == flcBlock[i].crc16)
          printf("  * CRC16 check OK\n");
        else
          printf("  * CRC16 check FAILED, actual CRC16 is 0x%04x instead of 0x%04x\n", blockCRC16, flcBlock[i].crc16);

        printf("\n\n");
	}

	fclose(flashFile);
	exit(0);
}

