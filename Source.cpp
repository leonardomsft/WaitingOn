#include "Header.h"

//Global definitions

//assures process info is printed just once
BOOL g_IsProcessPrinted = false;

// Global variable to store the WCT session handle
HWCT g_WctHandle = NULL;

//Function Prototypes
BOOL GrantDebugPrivilege();
void GetProcessNameFromPID(DWORD ProcId, PWSTR szExeName);
void PrintWaitChainForThread(DWORD ProcId, DWORD ThreadId);
BOOL CheckThreadsFromProcess(DWORD ProcId);
void Usage();


int wmain(int argc, wchar_t * argv[])
{

	printf("\nWritten by Leonardo Fagundes. No rights Reserved.\n");

	//Obtain Debug Priviledge
	if (!GrantDebugPrivilege())
	{
		printf("ERROR: Could not enable the debug privilege 0x%X\n", GetLastError());
	}

	// Open a synchronous WCT session.

	g_WctHandle = OpenThreadWaitChainSession(0, NULL);

	if (!g_WctHandle)
	{
		printf("ERROR: OpenThreadWaitChainSession failed\n");

		return -1;
	}

	// No arguments. Enumerate all processes in the system and call CheckThreadsFromProcess() for each one of them
	if (argc < 2)
	{
		
		DWORD processes[1024];
		HANDLE process;
		DWORD numProcesses;

		printf("\nWaitingOn.exe called with no arguments. Enumerating all blocked threads for all processes...\n");

		if (EnumProcesses(processes, sizeof(processes), &numProcesses) == false)
		{
			printf("ERROR: Could not enumerate processes 0x%X\n", GetLastError());

			return 1;
		}

		//Populate list of services
		GetServices();


		//walk through all processes
		for (int i = 0; i < numProcesses / sizeof(DWORD); i++)
		{

			//skipping myself and PID 0
			if ((processes[i] == GetCurrentProcessId()) || (processes[i] == 0))
			{
				continue;
			}

			//Attempt to get a handle to the process
			process = OpenProcess(PROCESS_ALL_ACCESS, false, processes[i]);

			if (process)
			{
				CheckThreadsFromProcess(processes[i]);

				g_IsProcessPrinted = false;
			}

		}

	}
	// An argument was passed. Only enumerate threads in the specified process.
	else
	{
		DWORD  ProcId = 0;

		ProcId = _wtoi(argv[1]);

		if (ProcId == 0)
		{
			Usage();

			return 1;
		}

		printf("\nEnumerating all blocked threads for the specified process...\n");

		HANDLE process;

		process = OpenProcess(PROCESS_ALL_ACCESS, false, ProcId);

		if (process)
		{
			CheckThreadsFromProcess(ProcId);
		}
		else
		{
			printf("\nError opening Process ID %d: 0x%X", ProcId, GetLastError());
		}

	}
	printf("\n");

	//Cleanup
	CloseThreadWaitChainSession(g_WctHandle);
	if (pSvcBuffer != NULL) LocalFree(pSvcBuffer);


}
