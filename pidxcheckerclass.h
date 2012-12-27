//---------------------------------------------------------------------------

#ifndef pidxcheckerclassH
#define pidxcheckerclassH
//---------------------------------------------------------------------------

#define PGX_OK				0x00000000
#define PGX_PKEYMISSING		0x80070002
#define PGX_MALFORMEDKEY	0x80070057
#define PGX_INVALIDKEY		0x8A010101
#define PGX_BLACKLISTEDKEY	0x0000000F

#define PVALID 				L"Valid"
#define PINVALID 			L"Invalid"
#define PMALFORMED			L"Malformed"
#define PERROR              L"ERROR"


#include <string.h>
#include <stdlib>
#include <vector>
#include <fstream>
#include <cryptlite\hmac.h>
#include <cryptlite\sha256.h>
#include <rapidxml\rapidxml.hpp>
#include <windows.h>
#include <wininet.h>

#pragma link "wininet.lib"





struct DigitalProductId {
	unsigned int uiSize;
	unsigned short MajorVersion;
	unsigned short MinorVersion;
	char szProductId[24];
	unsigned int uiKeyIdx;
	char szEditionId[16];
	BYTE bCdKey[16];
	unsigned int uiCloneStatus;
	unsigned int uiTime;
	unsigned int uiRandom;
	unsigned int uiLt;
	unsigned int uiLicenseData[2];
	char sOemId[8];
	unsigned int uiBundleId;
	char sHardwareIdStatic[8];
	unsigned int uiHardwareIdTypeStatic;
	unsigned int uiBiosChecksumStatic;
	unsigned int uiVolSerStatic;
	unsigned int uiTotalRamStatic;
	unsigned int uiVideoBiosChecksumStatic;
	char sHardwareIdDynamic[8];
	unsigned int uiHardwareIdTypeDynamic;
	unsigned int uiBiosChecksumDynamic;
	unsigned int uiVolSerDynamic;
	unsigned int uiTotalRamDynamic;
	unsigned int uiVideoBiosChecksumDynamic;
	unsigned int uiCRC32;

};

struct DigitalProductId4 {
	unsigned int uiSize;
	unsigned short MajorVersion;
	unsigned short MinorVersion;
	WCHAR szAdvancedPid[64];
	WCHAR szActivationId[64];
	WCHAR szOemID[8];
	WCHAR szEditionType[260];
	BYTE bIsUpgrade;
	BYTE bReserved[7];
	BYTE bCDKey[16];
	BYTE bCDKey256Hash[32];
	BYTE b256Hash[32];
	WCHAR szEditionId[64];
	WCHAR szKeyType[64];
	WCHAR szEULA[64];
};

#endif
