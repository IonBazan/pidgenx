// ---------------------------------------------------------------------------

#pragma hdrstop

#include "pidxcheckerclass.h"

// ---------------------------------------------------------------------------

using namespace std;
using namespace cryptlite;
using namespace rapidxml;

typedef HRESULT(__stdcall *PidGenXFn)(WCHAR* szProductKey, // Product Key to decode
	WCHAR* szPKeyConfigPath, // Path to "pkeyconfig.xrm-ms"
	WCHAR* szPID, // Microsoft Product ID Family (use "55041", "12345" or "XXXXX")
	string* OemId, // OEM ID - unknown (use NULL)
	WCHAR* szProductId, // Calculated Product ID ("55041-XXX-XXXXXXX-XXXXX")
	struct DigitalProductId* pDigPid, // Calculated DigitalProductId structure
	struct DigitalProductId4* pDigPid4 // Calculated DigitalProductId4 structure
	);

class PIDXChecker {

private:
	PidGenXFn g_pPidGenX;
	wchar_t* DLLPath;

	// Allocates and loads XML (XRM-MS) file to memory
	char * XMLToChar(const wchar_t* filename);

public:
	// Pointer to a function which outputs a line of wstring to the user
		void(__fastcall*ptrSay)(wstring);

	bool bCheckMAK; // Decides whether to check MAK count or not


	PIDXChecker(void(__fastcall *ptrSayFunction)(wstring), wchar_t* PathToDLL) {
		this->ptrSay = ptrSayFunction;
		this->bCheckMAK = true;
		this->DLLPath = PathToDLL;
	}

	HRESULT DecodeKey(WCHAR* wszKey, WCHAR* wszPKeyConfig);
	string GetDescription(wstring wszAID, wstring &wszEdi, wchar_t* wszPKeyConfig, string &szCID);
	string GetCount(wstring pid);

public:

};

HRESULT PIDXChecker::DecodeKey(WCHAR* wszKey, WCHAR* wszPKeyConfig) {
	// attempt loading pidgenx.dll
	HMODULE hPidGenX = LoadLibrary(this->DLLPath);
	if (hPidGenX == NULL) {
		this->ptrSay(L"Error: Could not load library - file not found?");
		return -1;
	}
	// Try to get function pointer
	g_pPidGenX = (PidGenXFn)GetProcAddress(hPidGenX, "PidGenX");
	if (g_pPidGenX == NULL) {
		this->ptrSay(L"Error: Could not load library - wrong file?");
		return -1;
	}
	WCHAR wszProductId[24];
	wszProductId[0] = L'\0';
	// not really used, as everything is in DigitalProductId4,
	DigitalProductId sDPid;
	sDPid.uiSize = sizeof(DigitalProductId);
	DigitalProductId4 sDPid4;
	sDPid4.uiSize = sizeof(DigitalProductId4);

	// Call PidGenX function
	HRESULT hResult = g_pPidGenX(wszKey, wszPKeyConfig, L"XXXXX", NULL, wszProductId, &sDPid, &sDPid4);

	wstring szValid;
	switch (hResult) {
	case PGX_OK:
		szValid = PVALID;
		break;
	case PGX_INVALIDKEY:
		szValid = PINVALID;
		break;
	case PGX_MALFORMEDKEY:
		szValid = PMALFORMED;
		break;
	default:
		szValid = PERROR;
		break;
	}
	this->ptrSay(L"Validity\t: " + szValid); //

	if (hResult == PGX_OK) {
		wstring szEdi = sDPid4.szEditionType;
		this->ptrSay(L"Product ID\t: " + wstring(wszProductId));
		this->ptrSay(L"Advanced ID\t: " + wstring(sDPid4.szAdvancedPid));
		this->ptrSay(L"Activation ID\t: " + wstring(sDPid4.szActivationId));
		string szCID;
		string szDescription = this->GetDescription(sDPid4.szActivationId, szEdi, wszPKeyConfig, szCID);
		this->ptrSay(L"Edition Type\t: " + wstring(szEdi.begin(), szEdi.end()));
		this->ptrSay(L"Description\t: " + wstring(szDescription.begin(), szDescription.end()));
		this->ptrSay(L"Edition ID\t: " + wstring(sDPid4.szEditionId));
		this->ptrSay(L"Key Type\t: " + wstring(sDPid4.szKeyType));
		this->ptrSay(L"EULA\t\t: " + wstring(sDPid4.szEULA));
		this->ptrSay(L"Crypto ID\t: " + wstring(szCID.begin(), szCID.end()));
		if (bCheckMAK && wstring(sDPid4.szKeyType) == L"Volume:MAK") {
			string Count = this->GetCount(sDPid4.szAdvancedPid);
			this->ptrSay(L"Activation Count: " + wstring(Count.begin(), Count.end()));
			if (Count == "Key blocked!")
				hResult = PGX_BLACKLISTEDKEY;
		}

	}
	this->ptrSay(L"");
	FreeLibrary(hPidGenX);
	return hResult;
}

string PIDXChecker::GetDescription(wstring wszAID, wstring &wszEdi, wchar_t* wszPKeyConfig, string &szCID) {
	string desc = "";
	string szEdi;
	string szAID(wszAID.begin(), wszAID.end());
	transform(szAID.begin(), szAID.end(), szAID.begin(), tolower);
	szAID = "{" + szAID + "}";
	char* xml = this->XMLToChar(wszPKeyConfig);
	xml_document<>doc;
	xml_node<> *rootNode;
	///parse the actual xml
	try {
		doc.parse<0>(xml);

		// root -> rg:licenseGroup
		rootNode = doc.first_node();
		if (rootNode) { // -> r:license
			rootNode = rootNode->first_node();
			if (rootNode) { // -> r:otherInfo
				rootNode = rootNode->last_node();
				if (rootNode) { // -> tm:infoTables
					rootNode = rootNode->first_node();
					if (rootNode) { // -> tm:infoList
						rootNode = rootNode->first_node();
						if (rootNode) { // -> tm:infoBin
							rootNode = rootNode->last_node();
							if (rootNode) {
								string val = rootNode->value();
								string decoded_str;
								// Decode the base64 value
								base64::decode(val, decoded_str);
								doc.clear();
								if (decoded_str.length()) {
									// Load it to char vector and try to parse
									vector<char>inner_xml(decoded_str.begin(), decoded_str.end());
									doc.parse<0>(&inner_xml[0]);
									// root -> pkc:ProductKeyConfiguration
									rootNode = doc.first_node();
									if (rootNode) { // -> pkc:Configurations
										rootNode = rootNode->first_node();
										if (rootNode) { // -> pkc:Configuration
										rootNode = rootNode->first_node();
										string szTemp;
										// iterate trough similar nodes (also named pkc:Configuration)
										for (xml_node<> *child = rootNode; child; child = child->next_sibling()) {
										if (child->first_node()) {
										szTemp = child->first_node()->value();
										transform(szTemp.begin(), szTemp.end(), szTemp.begin(), ::tolower);
										if (szTemp == szAID) {
										string prefix = child->name();
										// Find and use prefix ("pkc:" or "")
										int r = prefix.find("Configuration");
										if (r >= 0) {
										prefix.replace(r, 14, "");
										}
										if (child->first_node((prefix + "ProductDescription").c_str())) {
										desc = child->first_node((prefix + "ProductDescription").c_str())->value();
										}
										if (child->first_node((prefix + "RefGroupId").c_str())) {
										szCID = child->first_node((prefix + "RefGroupId").c_str())->value();
										}
										if (child->first_node((prefix + "EditionId").c_str())) {
										szEdi = child->first_node((prefix + "EditionId").c_str())->value();
										wszEdi = wstring(szEdi.begin(), szEdi.end());
										}
										break;
										}
										}
										}
										}
									}

								}
							}
						}
					}
				}
			}
		}

	}
	// Catch RapidXML errors
	catch (parse_error err) {
		MessageBoxA(NULL, err.what(), "XML Parse Error!", MB_OK);
		doc.clear();
		delete[]xml;
		return "";
	}
	// delete your allocated memory with XML file
	doc.clear();
	delete[]xml;
	return desc;
}

string PIDXChecker::GetCount(wstring wszPID) {
	wszPID.replace(0, 5, L"12345");
	int count = -1;
	string szReturnString = "Not Available";
	wstring szRequestInnerBody =
		L"<ActivationRequest xmlns=\"http://www.microsoft.com/DRM/SL/BatchActivationRequest/1.0\"><VersionNumber>2.0</VersionNumber><RequestType>2</RequestType><Requests><Request><PID>" +
		wszPID + L"</PID></Request></Requests></ActivationRequest>";

	byte* bSecretKey =
		"\xfe\x31\x98\x75\xfb\x48\x84\x86\x9c\xf3\xf1\xce\x99\xa8\x90\x64\xab\x57\x1f\xca\x47\x04\x50\x58\x30\x24\xe2\x14\x62\x87\x79\xa0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	byte * bRequestInnerBody = (byte*)(szRequestInnerBody.c_str());
	boost::uint8_t digest[32];

	hmac<sha256>::calc(bRequestInnerBody, szRequestInnerBody.length()*2, bSecretKey, 32, digest);
	string Digest = base64::encode_from_array(digest, 32).c_str();
	string Basec64 = base64::encode_from_array(bRequestInnerBody, szRequestInnerBody.length() * 2).c_str();
	string szFormData =
		"<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><soap:Body><BatchActivate xmlns=\"http://www.microsoft.com/BatchActivationService\"><request><Digest>" +
		Digest + "</Digest><RequestXml>" + Basec64 +
		"</RequestXml></request></BatchActivate></soap:Body></soap:Envelope>";
	static char hdrs[] =
		"Content-Type: text/xml; charset=utf-8\r\nSOAPAction: \"http://www.microsoft.com/BatchActivationService/BatchActivate\"\r\nExpect: 100-continue";
	char* frmdata = const_cast<char*>(szFormData.c_str());
	// for clarity, error-checking has been removed
	HINTERNET hSession =
		InternetOpenA("Mozilla/4.0 (compatible; MSIE 6.0; MS Web Services Client Protocol 4.0.30319.1)",
		// User Agent
		INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	HINTERNET hConnect = InternetConnectA(hSession, "activation.sls.microsoft.com", INTERNET_DEFAULT_HTTPS_PORT, NULL,
		NULL, INTERNET_SERVICE_HTTP, 0, 1);
	HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", "/BatchActivation/BatchActivation.asmx", "HTTP/1.1", NULL,
		NULL, INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 1);
	HttpSendRequestA(hRequest, hdrs, strlen(hdrs), frmdata, strlen(frmdata));
	char responseText[256]; // change to wchar_t for unicode
	DWORD responseTextSize = sizeof(responseText);
	HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE, &responseText, &responseTextSize, NULL);
	string response(responseText, responseTextSize);
	if (response == "200") {
		char* data = NULL;
		DWORD dataSize = 0;
		DWORD dwBytesRead = 0;
		DWORD dwBytesWritten = 0;

		do {
			char buffer[2000];
			InternetReadFile(hRequest, (LPVOID)buffer, sizeof(buffer), &dwBytesRead);
			char *tempData = new char[dataSize + dwBytesRead];
			memcpy(tempData, data, dataSize);
			memcpy(tempData + dataSize, buffer, dwBytesRead);
			delete[]data;
			// delete buffer;
			data = tempData;
			dataSize += dwBytesRead;
		}
		while (dwBytesRead);
		string page = string(data, dataSize);
		vector<char>inner_xml(page.begin(), page.end());
		xml_document<>doc;
		xml_node<> *rootNode;
		try {
			// Note that it will auto-parse HTML entities
			doc.parse<0>(&inner_xml[0]);
			// root -> soap:Envelope
			rootNode = doc.first_node();
			if (rootNode) { // -> soap:Body
				rootNode = rootNode->first_node();
				if (rootNode) { // -> BatchActivateResponse
					rootNode = rootNode->first_node();
					if (rootNode) { // -> BatchActivateResult
						rootNode = rootNode->first_node();
						if (rootNode) { // -> ResponseXml
							rootNode = rootNode->first_node();
							if (rootNode) {
								string value = rootNode->value();
								vector<char>inner_xml(value.begin(), value.end());
								doc.clear();
								doc.parse<0>(&inner_xml[0]);
								// root -> ActivationResponse
								rootNode = doc.first_node();
								if (rootNode) { // -> Responses
									rootNode = rootNode->last_node();
									if (rootNode) { // -> Response
										rootNode = rootNode->first_node();
										if (rootNode) { // -> ActivationRemaining
										rootNode = rootNode->first_node("ActivationRemaining");
										if (rootNode) { // ActivationRemaining->value
										szReturnString = rootNode->value();
										if (atoi(szReturnString.c_str()) < 0) {
										// -> ErrorInfo
										rootNode = rootNode->parent()->last_node();
										if (rootNode) { // -> ErrorCode
										rootNode = rootNode->first_node();
										if (rootNode) {
										if (string(rootNode->value()) == "0x67")
										szReturnString = "Key blocked!";
										else
										szReturnString = "Error " + string(rootNode->value());
										}
										}
										}
										}

										}
									}
								}

							}
						}
					}
				}
			}
		}
		catch (parse_error err) {
			MessageBoxA(NULL, err.what(), "XML Parse Error!", MB_OK);
			doc.clear();
			return "";
		}
		doc.clear();

	}

	InternetCloseHandle(hRequest);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hSession);
	return szReturnString;
}

char * PIDXChecker::XMLToChar(const wchar_t* filename) {
	char * memblock = NULL;
	ifstream file(filename, ios::in | ios::binary | ios::ate);
	if (file.is_open()) {
		size_t size = file.tellg();
		memblock = new char[size + 1];
		memblock[size] = '\0';
		file.seekg(0, ios::beg);
		file.read(&memblock[0], size);
		file.close();

	}
	return memblock;
}
