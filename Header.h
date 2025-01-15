#include <windows.h>
#include <wct.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <string>

//Global declaration
extern HWCT g_WctHandle;
extern bool g_IsProcessPrinted;
DWORD totalServicesCount = 0;
LPBYTE pSvcBuffer = NULL;
LPENUM_SERVICE_STATUS_PROCESS services = NULL;


typedef struct _STR_ARRAY
{
	CHAR Desc[32];
} STR_ARRAY;

//names for the different synchronization types.
STR_ARRAY STR_OBJECT_TYPE[] =
{
	{ "CriticalSection" },
	{ "SendMessage" },
	{ "Mutex" },
	{ "Alpc" },
	{ "COM" },
	{ "Thread" },
	{ "Process" },
	{ "Thread" },
	{ "ComActivation" },
	{ "Unknown" },
	{ "Max" }
};

STR_ARRAY STR_OBJECT_STATUS[] =
{
	{ "WctStatusNoAccess" },	// ACCESS_DENIED for this object
	{ "Running" },					// Thread status
	{ "Blocked" },					// Thread status
	{ "WctStatusPidOnly" },			// Thread status
	{ "WctStatusPidOnlyRpcss" },	// Thread status
	{ "Owned" },					// Dispatcher status
	{ "NotOwned" },					// Dispatcher status
	{ "Abandoned" },				// Dispatcher status
	{ "StatusUnknown" },			// All objects
	{ "WctStatusError" },			// All objects
};


BOOL GrantDebugPrivilege()
/*
Routine Description:
Enables the debug privilege (SE_DEBUG_NAME) for this process.
This is necessary if we want to retrieve wait chains for processes not owned by the current user.
Arguments:
None.
Return Value:
TRUE if this privilege could be enabled; FALSE otherwise.
*/
{
	BOOL IsElevated = false, fSuccess = false;
	HANDLE           TokenHandle = NULL;
	TOKEN_PRIVILEGES TokenPrivileges;
	TOKEN_ELEVATION Elevation;
	DWORD cbSize = sizeof(TOKEN_ELEVATION);


	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle))
	{
		printf("Could not get the process token");
		goto Cleanup;
	}

	TokenPrivileges.PrivilegeCount = 1;

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &TokenPrivileges.Privileges[0].Luid))
	{
		printf("Couldn't lookup SeDebugPrivilege name\n");
		goto Cleanup;
	}

	TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(TokenHandle,
		false,
		&TokenPrivileges,
		sizeof(TokenPrivileges),
		NULL,
		NULL))
	{
		printf("Could not grant the debug privilege\n");
		goto Cleanup;
	}

	//if not elevated, print a warning but allow it to continue
	fSuccess = true;

	//check for elevation

	if (!GetTokenInformation(TokenHandle, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))

		printf("Could not check for process elevation. Error 0x%X\n", GetLastError());

	else
		IsElevated = Elevation.TokenIsElevated;

	if (!IsElevated)
	{
		printf("\nWarning: WaitingOn.exe is not elevated. Only processes for the current user will be analyzed.\n");

	}

Cleanup:

	if (TokenHandle)
	{
		CloseHandle(TokenHandle);
	}

	return fSuccess;
}


bool GetProcessNameFromPID(DWORD ProcId, LPWSTR szExeName)
{
	if (ProcId == 0 || szExeName == nullptr) return false;

	HANDLE hProcess;
	WCHAR TempExepath[MAX_PATH] {0};
	LPWSTR pTempExeName = nullptr;


	// Get a handle to the process.
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, ProcId);

	if (hProcess == INVALID_HANDLE_VALUE) return false;

	if (GetProcessImageFileName(hProcess, TempExepath, ARRAYSIZE(TempExepath)) > 0)
	{
		pTempExeName = wcsrchr(TempExepath, L'\\') + 1;

		wcscpy_s(szExeName, MAX_PATH, pTempExeName);

		//For services, also add ServiceName
		for (int i = 0; i < totalServicesCount; ++i)
		{
			ENUM_SERVICE_STATUS_PROCESS service = services[i];

			if (service.ServiceStatusProcess.dwProcessId == ProcId)
			{

				wcsncat_s(szExeName, MAX_PATH, L", service ", MAX_PATH);

				wcsncat_s(szExeName, MAX_PATH, service.lpServiceName, MAX_PATH);

			}
		}

	}
	else {

		return false;
	}

	return true;

}



void PrintWaitChainForThread(DWORD ProcId, DWORD ThreadId)
/*
Routine Description:
Prints Wait Chain for the specified thread.
Arguments:
ThreadId--Specifies the thread ID to analyze.
Return Value:
(none)
*/
{
	WAITCHAIN_NODE_INFO NodeInfoArray[WCT_MAX_NODE_COUNT];
	BOOL	IsCycle;
	DWORD	Count = WCT_MAX_NODE_COUNT;
	WCHAR	szExeName[MAX_PATH] = {};


	// Make a synchronous call to GetThreadWaitChain to retrieve the wait chain
	if (!GetThreadWaitChain(g_WctHandle,
		NULL,
		WCTP_GETINFO_ALL_FLAGS,
		ThreadId,
		&Count,
		NodeInfoArray,
		&IsCycle))
	{
		printf("GetThreadWaitChain failed. Error 0x%x\n", GetLastError());
		return;
	}

	// Check if the wait chain is too big for the array we passed in.
	if (Count > WCT_MAX_NODE_COUNT)
	{
		printf("Wait chain is too big: %d\n", Count);
		Count = WCT_MAX_NODE_COUNT;
	}


	//only print blocked threads
	if (Count > 1)
	{
		//only print process name once
		if (!g_IsProcessPrinted)
		{
			if (GetProcessNameFromPID(ProcId, szExeName))
			{

				printf("\n\nProcess ID: %i (%S)", ProcId, szExeName);

				g_IsProcessPrinted = true;

			}
		}

		/*
		//simple node dumper
		printf("\n  Thread ID: %d has %d Nodes", ThreadId, Count);
		for (int i = 0; i < Count; i++) {
		printf("\n    Node#: %d, Process ID: %d, Thread ID: %d, ObjectType: %s, ObjectName: %S, ObjectStatus: %s, WaitTime: 0x%x",
		i,
		NodeInfoArray[i].ThreadObject.ProcessId,
		NodeInfoArray[i].ThreadObject.ThreadId,
		STR_OBJECT_TYPE[NodeInfoArray[i].ObjectType - 1].Desc,
		(NodeInfoArray[i].LockObject.ObjectName[1] == L'\0') ? _T("(Unnammed)") : NodeInfoArray[i].LockObject.ObjectName,
		STR_OBJECT_STATUS[NodeInfoArray[i].ObjectStatus - 1].Desc,
		NodeInfoArray[i].ThreadObject.WaitTime);
		}
		*/


		//iterate through all nodes
		for (int i = 0; i < Count; i = i + 2) {

			//blocked and there's more nodes
			if (NodeInfoArray[i].ObjectStatus == WctStatusBlocked && (i + 1 < Count))
			{

				//identation
				printf("\n    ");
				for (int j = 0; j < i / 2; j++)
					printf("   ");


				printf("%C-Thread ID: %d is waiting on a %s",
					192,
					NodeInfoArray[i].ThreadObject.ThreadId,
					STR_OBJECT_TYPE[NodeInfoArray[i + 1].ObjectType - 1].Desc);


				//blocked on a thread or a process 
				if ((NodeInfoArray[i + 1].ObjectType == WctThreadWaitType) || (NodeInfoArray[i + 1].ObjectType == WctProcessWaitType) || (NodeInfoArray[i + 1].ObjectType == WctThreadType))
				{
					//by a thread
					if (NodeInfoArray[i + 2].ThreadObject.ThreadId != 0)
					{
						//blocked by a thread from the same process
						if (NodeInfoArray[i + 2].ThreadObject.ProcessId == ProcId)
						{
							printf(" (TID: %d) from same process.", NodeInfoArray[i + 2].ThreadObject.ThreadId);
						}
						//blocked by a thread from another process
						else
						{
							GetProcessNameFromPID(NodeInfoArray[i + 2].ThreadObject.ProcessId, szExeName);

							printf(" (TID: %d) from another process (PID: %d) %S", NodeInfoArray[i + 2].ThreadObject.ThreadId, NodeInfoArray[i + 2].ThreadObject.ProcessId, szExeName);
						}
					}
					//by a process
					else
					{
						GetProcessNameFromPID(NodeInfoArray[i + 2].ThreadObject.ProcessId, szExeName);

						printf(" (PID: %d) %S", NodeInfoArray[i + 2].ThreadObject.ProcessId, szExeName);

					}
				}
				//blocked on a sync object
				else
				{
					//named
					if (NodeInfoArray[i + 1].LockObject.ObjectName[1] != L'\0') {

						printf(" (ObjectName: %S)", NodeInfoArray[i + 1].LockObject.ObjectName);
					}

					//owned
					if (NodeInfoArray[i + 1].ObjectStatus == WctStatusOwned)
					{
						printf(" which is currently owned");

						//by a thread
						if (NodeInfoArray[i + 2].ThreadObject.ThreadId != 0)
						{
							printf(" by Thread ID: %d", NodeInfoArray[i + 2].ThreadObject.ThreadId);

							//from the same process
							if (NodeInfoArray[i + 2].ThreadObject.ProcessId == ProcId)
							{
								printf(" from the same process");
							}
							//from another process
							else
							{
								GetProcessNameFromPID(NodeInfoArray[i + 2].ThreadObject.ProcessId, szExeName);

								printf(" from another process (PID: %d) %S", NodeInfoArray[i + 2].ThreadObject.ProcessId, szExeName);
							}
						}
						//by a process
						else
						{
							GetProcessNameFromPID(NodeInfoArray[i + 2].ThreadObject.ProcessId, szExeName);

							printf(" by Process ID: %d (%S)", NodeInfoArray[i + 2].ThreadObject.ProcessId, szExeName);

						}

					}

					//not owned
					else
					{
						printf(" which is currently %s", STR_OBJECT_STATUS[NodeInfoArray[i + 1].ObjectStatus - 1].Desc);
					}


				}


			}
			//not blocked OR no more nodes
			else
			{

			}

		}

	}


	// is this thread deadlocked?
	if (IsCycle)
	{
		printf(" Deadlock detected!");
	}
}


BOOL CheckThreadsFromProcess(DWORD ProcId)
/*
Routine Description:
Enumerate all the threads for the specified PID and the calls PrintWaitChain for each one of them.
Arguments:
ProcId--Specifies the process ID
Return Value:
TRUE if processes could be checked; FALSE if a general failure occurred.
*/
{
	DWORD processes[1024];
	DWORD numProcesses;

	HANDLE snapshot;

	//Creates a snapshot of the process to be examined
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, ProcId);

	if (snapshot)
	{
		THREADENTRY32 thread;
		thread.dwSize = sizeof(thread);

		// Walk the thread list 
		if (Thread32First(snapshot, &thread))
		{
			do
			{
				if (thread.th32OwnerProcessID == ProcId)
				{
					// Open a handle to this specific thread
					HANDLE threadHandle = OpenThread(THREAD_ALL_ACCESS,
						false,
						thread.th32ThreadID);

					if (threadHandle)
					{
						// Check whether the thread is still running
						DWORD exitCode;
						GetExitCodeThread(threadHandle, &exitCode);

						if (exitCode == STILL_ACTIVE)
						{
							// Print the wait chain.
							PrintWaitChainForThread(ProcId, thread.th32ThreadID);
						}

						CloseHandle(threadHandle);

					}

				}

			} while (Thread32Next(snapshot, &thread));

		}

		CloseHandle(snapshot);

	}

	return true;
}


void Usage()
/*
Routine Description:
Print usage information to stdout.
*/
{
	printf("\n");
	printf("WaitingOn displays all blocked threads and what they are Waiting On.\n");
	printf("Usage: WaitingOn.exe [PID] (optional) \n");
	printf("\t (no args)     - display all blocked threads for all processes\n");
	printf("\t PID (optional)- display all blocked threads for the specified Process ID\n\n");
	printf("\t Note: Access Denied (0x5) may occur for protected processes. \n\n");
}


void GetServices()
{
	SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);

	if (hSCM == NULL)
	{
		return;
	}

	DWORD bufferSize = 0;
	DWORD requiredBufferSize = 0;
	DWORD dwRet = NULL;

	if (!EnumServicesStatusEx(hSCM,
		SC_ENUM_PROCESS_INFO,
		SERVICE_WIN32,
		SERVICE_STATE_ALL,
		nullptr,
		bufferSize,
		&requiredBufferSize,
		&totalServicesCount,
		nullptr,
		nullptr))
	{
		dwRet = GetLastError();

		if (dwRet != ERROR_MORE_DATA)
		{
			wprintf(L"EnumServicesStatusEx. ERROR: %d. Exiting.\n", dwRet);

			return;

		}

	}


	bufferSize = requiredBufferSize;

	//Allocate a buffer
	pSvcBuffer = (LPBYTE)LocalAlloc(LMEM_ZEROINIT, requiredBufferSize);

	if (pSvcBuffer == NULL)
	{
		wprintf(L"HeapAlloc. ERROR: %d. Exiting.\n", GetLastError());

		return;
	}



	if (!EnumServicesStatusEx(hSCM,
		SC_ENUM_PROCESS_INFO,
		SERVICE_WIN32,
		SERVICE_STATE_ALL,
		pSvcBuffer,
		bufferSize,
		&requiredBufferSize,
		&totalServicesCount,
		nullptr,
		nullptr))
	{
		dwRet = GetLastError();

		if (dwRet != ERROR_MORE_DATA)
		{
			wprintf(L"EnumServicesStatusEx. ERROR: %d. Exiting.\n", dwRet);

			return;

		}

	}

	services = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESS>(pSvcBuffer);

	CloseServiceHandle(hSCM);

}