#include <stdio.h>
#include <windows.h>
#include <winternl.h>

#define STATUS_NO_MORE_FILES ((NTSTATUS)0x80000006L)
#define STATUS_NO_SUCH_FILE ((NTSTATUS)0xC000000FL)
#define FileFullDirectoryInformation 2

typedef NTSTATUS(__stdcall* NT_OPEN_FILE)(OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock, IN ULONG ShareAccess, IN ULONG OpenOptions);
NT_OPEN_FILE NtOpenFileStruct; //to call dynamically loaded NtOpenFile

PUCHAR Buffer = NULL; //scan result blob
ULONG BufferLength = 0; //size of the blob to be filled during scan
BOOLEAN first = TRUE; //to know if we are re-starting the directory scan
IO_STATUS_BLOCK IoStatusBlock = { 0 };	//status block to indicate the final status of an I/O request
UNICODE_STRING DirectoryName; //name of the dir used to initialize object attributes
OBJECT_ATTRIBUTES ObjAttr; //structure expected by NtOpenFile
HANDLE hDir; //handle to the directory to scan with NtQueryDirectoryFile
PFILE_FULL_DIR_INFO DirInformation; //structured result of the dir scan
ANSI_STRING as; //to display ansi with printf
UNICODE_STRING EntryName; //name of the entry (file or folder) within directory
NTSTATUS Status; //to check how the API call went
HANDLE hToken; //process token
HANDLE hModule; //handle to ntdll 

BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege)   // to enable or disable privilege
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}


int main()
{
	if (!OpenProcessToken(
		GetCurrentProcess(), 
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken))
	{
		printf("OpenProcessToken() failed with code %d\n", GetLastError());
		exit(-1);
	}

	if (!SetPrivilege(hToken, "SeBackupPrivilege", TRUE)) 
	{
		printf("The token operation failed. \n");
		exit(-1);
	}

	hModule = LoadLibrary("ntdll.dll"); 
	if (hModule == NULL)
	{
		printf("Error: could not load ntdll.dll.");
		exit(-1);
	}

	NtOpenFileStruct = (NT_OPEN_FILE)GetProcAddress(hModule, "NtOpenFile");
	if (NtOpenFileStruct == NULL) 
	{
		printf("Error: could not find the function NtOpenFile in library ntdll.dll.");
		exit(-1);
	}

	RtlInitUnicodeString(&DirectoryName, L"\\DosDevices\\C:\\test\\"); //intentionally hardcoded
	
	InitializeObjectAttributes(
		&ObjAttr,
		&DirectoryName,
		OBJ_CASE_INSENSITIVE,
		NULL, // absolute open, no relative directory handle
		NULL); // no security descriptor necessary

	Status = NtOpenFile(
		&hDir, //FileHandle
		FILE_LIST_DIRECTORY | SYNCHRONIZE, //DesiredAccess
		&ObjAttr, //ObjectAttributes
		&IoStatusBlock, //IoStatusBlock
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, //ShareAccess
		FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT); //OpenOptions

	if (!NT_SUCCESS(Status)) 
	{
		printf("File could not be opened - error: %d\n", RtlNtStatusToDosError(Status));
		exit(-1);
	}

	BufferLength = 64 * 1024;
	Buffer = (PUCHAR)malloc(BufferLength);
	if (Buffer == NULL) 
	{
		printf("Buffer could not be alocated.\n");
		exit(-1);
	}

	first = TRUE; //starting the new scan

	while (1) 
	{
		Status = NtQueryDirectoryFile(
			hDir, //FileHandle
			NULL, //Event
			NULL, //ApcRoutine
			NULL, //ApcContext
			&IoStatusBlock, //IoStatusBlock
			Buffer, //FileInformation
			BufferLength, //Length
			FileFullDirectoryInformation, //FileInformationClass
			FALSE, //ReturnSingleEntry
			NULL, //FileName
			first); //RestartScan

		if (Status == STATUS_NO_MORE_FILES || Status == STATUS_NO_SUCH_FILE) 
		{
			break;
		}
		if (!NT_SUCCESS(Status)) 
		{
			printf("NtQueryDirectoryFile error: %d\n", RtlNtStatusToDosError(Status));
			exit(-1);
		}

		first = FALSE; //we will continue the scan
		DirInformation = (PFILE_FULL_DIR_INFO)Buffer;

		while (1) //iterate through collected data and display names
		{
			EntryName.MaximumLength = EntryName.Length = (USHORT)DirInformation->FileNameLength;
			EntryName.Buffer = &DirInformation->FileName[0];
			RtlUnicodeStringToAnsiString(&as, &EntryName, TRUE);
			if (DirInformation->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				printf("Directory name: ");
			else 
				printf("Filename: ");
			printf("%s\n", as.Buffer);

			if (DirInformation->NextEntryOffset == 0)
				break;
			else
				DirInformation = (PFILE_FULL_DIR_INFO)(((PUCHAR)DirInformation) + DirInformation->NextEntryOffset);
		}
	}
}
