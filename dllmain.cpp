///////////////////////////////////////////////////////////////////////////////
// dllmain.cpp
// Combined ASI for Runtime Patching and Static File Patch Generation
// Includes INI Auto-Creation, INI Control (Static Patch & Console),
// Dedicated Static Patch Log, PE Parsing, and Verification
// VERSION: Full Code (INI Auto-Create & Console Control)
///////////////////////////////////////////////////////////////////////////////

// --- Precompiled Header ---
#include "pch.h" // Ensure this includes necessary headers like windows.h

// --- Standard Library Includes ---
#include <windows.h>    // For WinAPI functions and PE structures
#include <winnt.h>      // For PE structures (IMAGE_NT_HEADERS, etc.)
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>   // Requires C++17 standard in project settings
#include <iostream>
#include <optional>
#include <sstream>      // For FindPatternInFileBuffer
#include <iomanip>      // For FindPatternInFileBuffer & Verification Logging
#include <system_error> // For std::error_code with filesystem::remove
#include <Shlwapi.h>    // For PathRemoveFileSpecA, PathAppendA (Link Shlwapi.lib)
#include <limits>       // For numeric_limits (used in optional console pause)
#include <cctype>       // For std::tolower

// --- Project Headers ---
// These must exist in your project and provide the necessary functions
#include "patches.h"    // Expected: void DisableSignatureCheck(const char*); void DisableChunkSigCheck(const char*, const char*);
#include "utils.h"      // Expected: std::string GetProcessName(); (or similar)


// --- Global Variables ---
constexpr const char* ASI_VERSION = "1.2.0"; // Version of this ASI mod
bool bPauseOnStart = false; // If true, shows a MessageBox to allow debugger attachment
bool bShowConsole = true;   // << Default value, will be overwritten by INI >>
bool bAttemptStaticPatch = false; // << Default value, will be overwritten by INI >>
HMODULE g_hModule = NULL;   // Handle to this DLL module, set in DllMain

// For log file redirection
std::ofstream g_logFileStream;
std::streambuf* g_origCoutBuf = nullptr;
std::streambuf* g_origCerrBuf = nullptr;

// INI File Defaults
const char* INI_FILENAME = "UESigPatchTCMPakbypass.ini";
const char* DEFAULT_CREATE_PATCHED_EXE = "false"; // Default to false
const char* DEFAULT_SHOW_CONSOLE = "true";       // Default to true

// --- Game Version Enum ---
enum eSupportedGames {
    eGameTcmXbox,
    eGameTcmSteam,
    eUnsupportedGame
};


// --- Function Implementations ---

/**
 * @brief Determines the game type based on the executable filename.
 * @param sProcessName The filename of the current process executable.
 * @return eSupportedGames enum value.
 */
eSupportedGames GetEnumeratorFromProcessName(const std::string& sProcessName) {
    if (sProcessName == "BBQClient-WinGDK-Shipping.exe") return eGameTcmXbox;
    if (sProcessName == "BBQClient-Win64-Shipping.exe") return eGameTcmSteam;
    return eUnsupportedGame;
}

/**
 * @brief Creates and sets up a console window for logging output (stdout/stderr).
 */
void CreateConsole()
{
    if (GetConsoleWindow() == NULL)
    {
        if (!AllocConsole()) {
            MessageBoxA(NULL, "Failed to allocate console window.", "Console Error", MB_OK | MB_ICONERROR);
            return;
        }
    }

    FILE* fNull = nullptr; // Initialize to nullptr
    // Redirect standard output streams to the new console window
    if (freopen_s(&fNull, "CONOUT$", "w", stdout) != 0) { OutputDebugStringA("Failed to redirect stdout to console.\n"); }
    if (freopen_s(&fNull, "CONOUT$", "w", stderr) != 0) { OutputDebugStringA("Failed to redirect stderr to console.\n"); }
    // if (freopen_s(&fNull, "CONIN$", "r", stdin) != 0) { /* Handle error */ }

    // Set console title
    std::string consoleName = "UESigPatchTCMPakbypass Console";
    SetConsoleTitleA(consoleName.c_str());

    // Enable ANSI escape code processing (optional)
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hConsole, &dwMode)) {
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hConsole, dwMode);
        }
    }
    // Clear potential error states and synchronize C++ streams
    std::cout.clear();
    std::cerr.clear();
    std::cin.clear();
    std::ios::sync_with_stdio(true);
}

/**
 * @brief Searches a byte buffer for a pattern string (e.g., "48 89 ? AB").
 * @param buffer The byte buffer (file content) to search within.
 * @param patternString The IDA-style pattern string. '?' or '??' are wildcards.
 * @return std::optional<size_t> containing the offset if found, std::nullopt otherwise.
 */
std::optional<size_t> FindPatternInFileBuffer(const std::vector<unsigned char>& buffer, const char* patternString) {
    std::vector<unsigned char> patternBytes;
    std::vector<bool> patternMask;

    std::stringstream ss(patternString);
    std::string byteStr;

    // Parse pattern string into bytes and mask
    while (ss >> byteStr) {
        if (byteStr == "?" || byteStr == "??") {
            patternBytes.push_back(0);
            patternMask.push_back(true);
        }
        else {
            try {
                // Use unsigned long for intermediate parsing, then check range
                unsigned long byteValueLong = std::stoul(byteStr, nullptr, 16);
                if (byteValueLong > 0xFF) throw std::out_of_range("Byte value > FF");
                patternBytes.push_back(static_cast<unsigned char>(byteValueLong));
                patternMask.push_back(false);
            }
            catch (const std::invalid_argument& e) {
                // Use cerr for logging errors, which might be redirected
                std::cerr << "[Pattern] Error parsing '" << byteStr << "' (Invalid Argument): " << e.what() << std::endl;
                return std::nullopt;
            }
            catch (const std::out_of_range& e) {
                std::cerr << "[Pattern] Error parsing '" << byteStr << "' (Out Of Range): " << e.what() << std::endl;
                return std::nullopt;
            }
        }
    }

    if (patternBytes.empty()) {
        std::cerr << "[Pattern] Empty pattern provided." << std::endl;
        return std::nullopt;
    }
    if (patternBytes.size() > buffer.size()) {
        // Don't log this as an error, just return not found
        // std::cerr << "[Pattern] Pattern size exceeds buffer size." << std::endl;
        return std::nullopt;
    }

    // Search the buffer
    // Optimization: check if buffer is smaller than pattern after parsing
    if (buffer.size() < patternBytes.size()) {
        return std::nullopt;
    }
    size_t searchLimit = buffer.size() - patternBytes.size();
    for (size_t i = 0; i <= searchLimit; ++i) {
        bool found = true;
        for (size_t j = 0; j < patternBytes.size(); ++j) {
            if (!patternMask[j] && buffer[i + j] != patternBytes[j]) {
                found = false;
                break;
            }
        }
        if (found) {
            return i; // Return first matching offset
        }
    }

    return std::nullopt; // Pattern not found
}

/**
 * @brief Patches a value of type T into a byte buffer at a given offset.
 * @tparam T The type of data to patch (e.g., uint8_t, uint32_t, int32_t).
 * @param buffer The byte buffer (file content) to modify.
 * @param fileOffset The offset within the buffer where patching should start.
 * @param value The value to write into the buffer.
 * @return True if patching was successful, false otherwise (e.g., out of bounds).
 */
template <typename T>
bool PatchFileBuffer(std::vector<unsigned char>& buffer, size_t fileOffset, T value) {
    if ((fileOffset + sizeof(T)) > buffer.size()) {
        std::cerr << "[StaticPatcher] PatchFileBuffer<" << typeid(T).name() << "> error: Offset 0x" << std::hex << fileOffset << " + size " << std::dec << sizeof(T) << " exceeds buffer size (" << buffer.size() << ")." << std::endl;
        return false;
    }
    *reinterpret_cast<T*>(&buffer[fileOffset]) = value;
    return true;
}

/**
 * @brief Patches a single byte into a byte buffer at a given offset. Convenience wrapper.
 * @param buffer The byte buffer (file content) to modify.
 * @param fileOffset The offset within the buffer where patching should occur.
 * @param value The byte value to write.
 * @return True if patching was successful, false otherwise (e.g., out of bounds).
 */
bool PatchFileBufferByte(std::vector<unsigned char>& buffer, size_t fileOffset, unsigned char value) {
    // Explicit bounds check for single byte
    if (fileOffset >= buffer.size()) {
        std::cerr << "[StaticPatcher] PatchFileBufferByte error: Offset 0x" << std::hex << fileOffset << " exceeds buffer size (" << std::dec << buffer.size() << ")." << std::endl;
        return false;
    }
    buffer[fileOffset] = value;
    return true;
    // Or use template: return PatchFileBuffer<unsigned char>(buffer, fileOffset, value);
}

/**
 * @brief Converts a file offset within the buffer to a Relative Virtual Address (RVA).
 *        Requires valid PE headers pointed to by pNtHeaders.
 * @param fileOffset The raw file offset within the buffer.
 * @param buffer The vector containing the PE file data.
 * @param pNtHeaders A pointer to the validated IMAGE_NT_HEADERS64 structure within the buffer.
 * @return std::optional<DWORD> containing the calculated RVA if the offset is within a section, std::nullopt otherwise.
 */
std::optional<DWORD> FileOffsetToRVA(size_t fileOffset, const std::vector<unsigned char>& buffer, PIMAGE_NT_HEADERS64 pNtHeaders) {
    if (!pNtHeaders || fileOffset >= buffer.size()) {
        return std::nullopt; // Basic validation
    }

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    WORD numSections = pNtHeaders->FileHeader.NumberOfSections;

    for (WORD i = 0; i < numSections; ++i) {
        DWORD sectionRawStart = pSectionHeader[i].PointerToRawData;
        DWORD sectionRawSize = pSectionHeader[i].SizeOfRawData;
        // Skip sections with no raw data or invalid pointers
        if (sectionRawSize == 0 || sectionRawStart == 0) continue;

        DWORD sectionRawEnd = sectionRawStart + sectionRawSize;

        // Check if the file offset falls within this section's raw data range
        if (fileOffset >= sectionRawStart && fileOffset < sectionRawEnd) {
            DWORD offsetInSection = static_cast<DWORD>(fileOffset - sectionRawStart);
            // Ensure calculated RVA doesn't exceed section's virtual size (optional but safer)
            if (offsetInSection < pSectionHeader[i].Misc.VirtualSize) {
                DWORD rva = pSectionHeader[i].VirtualAddress + offsetInSection;
                // Log the successful mapping (optional)
                if (bShowConsole || g_logFileStream.is_open()) { // Log if console or file log active
                    char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
                    strncpy_s(sectionName, (const char*)pSectionHeader[i].Name, IMAGE_SIZEOF_SHORT_NAME);
                    // Select output stream based on redirection state
                    std::ostream& out = (g_origCoutBuf) ? std::cout : (bShowConsole ? std::cout : std::cerr); // Prefer cout if available
                    out << "[PE] File offset 0x" << std::hex << fileOffset
                        << " maps to RVA 0x" << rva
                        << " (Section: " << sectionName << ")" << std::dec << std::endl;
                }
                return rva; // Return the calculated RVA
            }
            else {
                // Offset is within raw data range but exceeds virtual size - indicates padding?
                std::cerr << "[PE] Warning: File offset 0x" << std::hex << fileOffset
                    << " is within raw data of section " << (const char*)pSectionHeader[i].Name
                    << " but exceeds its virtual size (0x" << pSectionHeader[i].Misc.VirtualSize << ")." << std::dec << std::endl;
                // Continue searching other sections just in case, though unlikely to be correct
            }
        }
    }
    std::cerr << "[PE] Warning: File offset 0x" << std::hex << fileOffset << " not found within any section's defined raw data." << std::dec << std::endl;
    return std::nullopt; // Not found in any section
}

/**
 * @brief Gets the full path to the INI file located next to the DLL.
 * @param iniPathBuffer Buffer to store the resulting path.
 * @param bufferSize Size of the buffer.
 * @return True if the path was successfully obtained, false otherwise.
 */
bool GetIniPath(char* iniPathBuffer, size_t bufferSize) {
    if (!g_hModule || !iniPathBuffer || bufferSize < MAX_PATH) return false;
    DWORD pathLen = GetModuleFileNameA(g_hModule, iniPathBuffer, static_cast<DWORD>(bufferSize));
    if (pathLen == 0 || pathLen >= bufferSize) { // Check for errors or buffer overflow
        return false;
    }
    if (!PathRemoveFileSpecA(iniPathBuffer)) { // Remove DLL filename
        return false;
    }
    if (!PathAppendA(iniPathBuffer, INI_FILENAME)) { // Append INI filename
        return false;
    }
    return true;
}

/**
 * @brief Creates the INI file with default settings if it doesn't exist.
 */
void WriteDefaultConfig() {
    char iniPath[MAX_PATH] = { 0 };
    if (!GetIniPath(iniPath, MAX_PATH)) {
        OutputDebugStringA("[Config] WriteDefaultConfig: Failed to determine INI path.\n");
        return;
    }

    // Check if INI file already exists using std::filesystem for clarity
    std::error_code ec;
    bool fileExists = std::filesystem::exists(iniPath, ec);

    if (!fileExists && !ec) { // Only write if file doesn't exist and no error checking existence
        OutputDebugStringA(("[Config] INI file not found. Creating default: " + std::string(iniPath) + "\n").c_str());
        // Write default values using safe API
        WritePrivateProfileStringA("Settings", "CreatePatchedExe", DEFAULT_CREATE_PATCHED_EXE, iniPath);
        WritePrivateProfileStringA("Settings", "ShowConsole", DEFAULT_SHOW_CONSOLE, iniPath);
        // Add comments explaining the settings
        WritePrivateProfileStringA("Settings", "; Help", "----------------------------------------------------------------", iniPath);
        WritePrivateProfileStringA("Settings", "; CreatePatchedExe", "Set to true/1/yes to generate a patched EXE file on launch.", iniPath);
        WritePrivateProfileStringA("Settings", "; ShowConsole", "Set to true/1/yes to show a console window for logs.", iniPath);
        WritePrivateProfileStringA("Settings", "; HelpEnd", "----------------------------------------------------------------", iniPath);

    }
    else if (ec) {
        OutputDebugStringA(("[Config] Error checking INI file existence: " + ec.message() + "\n").c_str());
    }
}


/**
 * @brief Reads configuration settings from the INI file, updating global variables.
 *        Handles boolean string values like "true"/"false".
 */
void ReadConfig() {
    char iniPath[MAX_PATH] = { 0 };
    if (!GetIniPath(iniPath, MAX_PATH)) {
        OutputDebugStringA("[Config] ReadConfig: Failed to determine INI path. Using defaults.\n");
        // Apply hardcoded defaults if INI path fails
        bAttemptStaticPatch = (std::string(DEFAULT_CREATE_PATCHED_EXE) == "true" || std::string(DEFAULT_CREATE_PATCHED_EXE) == "1" || std::string(DEFAULT_CREATE_PATCHED_EXE) == "yes");
        bShowConsole = (std::string(DEFAULT_SHOW_CONSOLE) == "true" || std::string(DEFAULT_SHOW_CONSOLE) == "1" || std::string(DEFAULT_SHOW_CONSOLE) == "yes");
        return;
    }

    char valueBuffer[32]; // Buffer for reading string values

    // --- Read CreatePatchedExe setting ---
    GetPrivateProfileStringA("Settings", "CreatePatchedExe", DEFAULT_CREATE_PATCHED_EXE,
        valueBuffer, sizeof(valueBuffer), iniPath);
    std::string createExeStr(valueBuffer);
    for (char& c : createExeStr) { c = static_cast<char>(std::tolower(static_cast<unsigned char>(c))); }
    bAttemptStaticPatch = (createExeStr == "true" || createExeStr == "1" || createExeStr == "yes");

    // --- Read ShowConsole setting ---
    GetPrivateProfileStringA("Settings", "ShowConsole", DEFAULT_SHOW_CONSOLE,
        valueBuffer, sizeof(valueBuffer), iniPath);
    std::string showConsoleStr(valueBuffer);
    for (char& c : showConsoleStr) { c = static_cast<char>(std::tolower(static_cast<unsigned char>(c))); }
    bShowConsole = (showConsoleStr == "true" || showConsoleStr == "1" || showConsoleStr == "yes");

    // Config values are now set globally (bShowConsole, bAttemptStaticPatch)
    // Logging the values read happens in Initialize() after console is potentially created.
}

/**
 * @brief Sets up redirection of std::cout and std::cerr to the static patch log file.
 * @return True if redirection was successful, false otherwise.
 */
bool SetupStaticPatchLogging() {
    char logPath[MAX_PATH] = { 0 };
    if (GetIniPath(logPath, MAX_PATH)) { // Reuse GetIniPath logic to get dir
        // Replace INI filename with log filename
        PathRemoveFileSpecA(logPath);
        PathAppendA(logPath, "UESigPatchTCMPakbypass_StaticPatch.log");

        g_logFileStream.open(logPath, std::ios::out | std::ios::trunc);
        if (g_logFileStream.is_open()) {
            g_origCoutBuf = std::cout.rdbuf(g_logFileStream.rdbuf()); // Redirect cout, store original
            g_origCerrBuf = std::cerr.rdbuf(g_logFileStream.rdbuf()); // Redirect cerr, store original
            std::cout << "--- UESigPatchTCMPakbypass Static Patch Log (" << ASI_VERSION << ") ---" << std::endl;

            // --- CORRECTED TIMESTAMP CODE ---
            // 1. Get the current time as a time_t value
            std::time_t now_c = std::time(nullptr); // Or std::time(0)

            // 2. Create a tm struct to hold the broken-down time
            std::tm now_tm = {}; // Use {} to value-initialize (zeroes out members)

            // 3. Convert time_t to tm using the safer localtime_s (Windows specific)
            errno_t err = localtime_s(&now_tm, &now_c); // Pass pointers

            // 4. Check if conversion was successful and print timestamp
            if (err == 0) {
                std::cout << "Timestamp: " << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S") << std::endl; // Pass pointer to tm struct
            }
            else {
                std::cerr << "[Logging] Error: Failed to get local time for timestamp (errno=" << err << ")." << std::endl;
            }
            // --- END CORRECTION ---

            return true; // Redirection successful
        }
        else {
            // Cannot open log file, report error (using debug output as streams might be bad)
            OutputDebugStringA(("[Logging] Error: Failed to open static patch log file: " + std::string(logPath) + "\n").c_str());
            return false;
        }
    }
    else {
        OutputDebugStringA("[Logging] Error: Could not get DLL module path to create log file.\n");
        return false;
    }
}

/**
 * @brief Restores std::cout and std::cerr to their original stream buffers and closes the log file.
 */
void RestoreConsoleLogging() {
    if (g_origCoutBuf || g_origCerrBuf) {
        if (g_logFileStream.is_open()) {
            // Log end marker before restoring
            std::cout << "--- Static Patch Log Ended ---" << std::endl;
            std::cout.flush(); // Ensure buffer is written
            std::cerr.flush();
        }
        // Restore original buffers if they were saved
        if (g_origCoutBuf) std::cout.rdbuf(g_origCoutBuf);
        if (g_origCerrBuf) std::cerr.rdbuf(g_origCerrBuf);
        // Close the file stream
        if (g_logFileStream.is_open()) g_logFileStream.close();
        // Clear pointers to indicate restoration
        g_origCoutBuf = nullptr;
        g_origCerrBuf = nullptr;
    }
}

/**
 * @brief Reads the original game executable, applies AND VERIFIES patches
 *        (including relative patches using PE parsing) to its content in memory,
 *        and writes the result to a new file named *_patched.exe.
 *        Logs detailed steps to std::cout/std::cerr (which might be redirected).
 * @return True if the patched executable was successfully created and verified, false otherwise.
 */
bool CreatePatchedExecutable() {
    // All std::cout/cerr calls within this function will go to the log file
    // if SetupStaticPatchLogging() was called successfully before this.

    char processPath[MAX_PATH];
    if (GetModuleFileNameA(NULL, processPath, MAX_PATH) == 0) {
        std::cerr << "[StaticPatcher] Failed to get process module path. Error: " << GetLastError() << std::endl;
        return false;
    }
    std::filesystem::path exeFullPath(processPath);
    std::filesystem::path dirPath = exeFullPath.parent_path();
    std::string baseFilename = exeFullPath.stem().string();
    std::string extension = exeFullPath.extension().string();
    std::filesystem::path patchedExePath = dirPath / (baseFilename + "_patched" + extension);

    std::cout << "[StaticPatcher] Attempting to create patched file: " << patchedExePath << std::endl;

    // --- 1. Read Original Executable ---
    std::ifstream inFile(exeFullPath, std::ios::binary | std::ios::ate);
    if (!inFile) { std::cerr << "[StaticPatcher] Error: Cannot open original executable: " << exeFullPath << std::endl; return false; }
    std::streamsize streamSize = inFile.tellg();
    inFile.seekg(0, std::ios::beg);
    if (streamSize <= 0) { std::cerr << "[StaticPatcher] Error: Invalid file size: " << streamSize << std::endl; inFile.close(); return false; }
    size_t fileSize = static_cast<size_t>(streamSize);
    if (fileSize < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64)) { std::cerr << "[StaticPatcher] Error: File too small." << std::endl; inFile.close(); return false; }
    std::vector<unsigned char> fileBuffer(fileSize);
    if (!inFile.read(reinterpret_cast<char*>(fileBuffer.data()), streamSize)) { std::cerr << "[StaticPatcher] Error: Cannot read executable." << std::endl; inFile.close(); return false; }
    inFile.close();
    std::cout << "[StaticPatcher] Read " << fileSize << " bytes from original executable." << std::endl;


    // --- 2. Validate PE Headers ---
    if (fileBuffer[0] != 'M' || fileBuffer[1] != 'Z') { std::cerr << "[PE] Error: Invalid DOS signature." << std::endl; return false; }
    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(fileBuffer.data());
    DWORD peHeaderOffset = pDosHeader->e_lfanew;
    if (peHeaderOffset == 0 || (peHeaderOffset + sizeof(IMAGE_NT_HEADERS64)) > fileBuffer.size()) { std::cerr << "[PE] Error: Invalid PE header offset." << std::endl; return false; }
    PIMAGE_NT_HEADERS64 pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(&fileBuffer[peHeaderOffset]);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) { std::cerr << "[PE] Error: Invalid NT signature." << std::endl; return false; }
    if (pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) { std::cerr << "[PE] Error: Not 64-bit PE." << std::endl; return false; }
    std::cout << "[PE] PE Headers validated successfully." << std::endl;


    // --- 3. Apply Patches WITH VERIFICATION ---
    bool patchesAppliedSuccessfully = false;
    eSupportedGames gameType = GetEnumeratorFromProcessName(exeFullPath.filename().string());
    const char* pSigCheck = "80 B9 ? ? ? ? 00 49 8B F0 48 8B FA 48 8B D9 75";
    const char* pChunkSigCheck = "0F B6 51 ? 48 8B F1 48 8B 0D ? ? ? ? E8 ? ? ? ? C6 46 ? ? 0F AE F8";
    const char* pChunkSigCheckFunc = "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC 20 48 8D 59 08 49 63 F9 48 8B F1 49 8B E8 48 8B CB 44 0F B6 F2";
    bool sigCheckPatchVerified = false;
    bool chunkSigCheckPatchVerified = false;

    if (gameType == eGameTcmXbox || gameType == eGameTcmSteam) {

        // --- Apply/Verify SigCheck Patch ---
        std::optional<size_t> sigCheckOffsetOpt = FindPatternInFileBuffer(fileBuffer, pSigCheck);
        if (sigCheckOffsetOpt) {
            size_t sigCheckOffset = *sigCheckOffsetOpt;
            std::cout << "[StaticPatcher] SigCheck pattern found at file offset 0x" << std::hex << sigCheckOffset << std::dec << "." << std::endl;
            size_t patchFileOffset = sigCheckOffset - 0x14;
            const size_t patchSize = 1 + sizeof(uint32_t);
            if (patchFileOffset < fileBuffer.size() && (patchFileOffset + patchSize) <= fileBuffer.size()) {
                std::cout << "[StaticPatcher]   Original bytes at offset 0x" << std::hex << patchFileOffset << ":";
                for (size_t i = 0; i < patchSize; ++i) std::cout << " " << std::setw(2) << std::setfill('0') << static_cast<int>(fileBuffer[patchFileOffset + i]);
                std::cout << std::dec << std::endl;
                bool patchByteOk = PatchFileBufferByte(fileBuffer, patchFileOffset, 0xC3);
                bool patchDwordOk = PatchFileBuffer<uint32_t>(fileBuffer, patchFileOffset + 1, 0x90909090);
                if (patchByteOk && patchDwordOk) {
                    std::cout << "[StaticPatcher]   Patch applied to buffer. Verifying..." << std::endl;
                    unsigned char byteAfter = fileBuffer[patchFileOffset];
                    uint32_t dwordAfter = *reinterpret_cast<uint32_t*>(&fileBuffer[patchFileOffset + 1]);
                    sigCheckPatchVerified = (byteAfter == 0xC3 && dwordAfter == 0x90909090);
                    if (sigCheckPatchVerified) { std::cout << "[StaticPatcher]   VERIFIED! SigCheck patch successful." << std::endl; }
                    else { std::cerr << "[StaticPatcher]   VERIFICATION FAILED! SigCheck patch incorrect after write." << std::endl; }
                }
                else { std::cerr << "[StaticPatcher]   Failed patching SigCheck in buffer (Patch call failed)." << std::endl; }
            }
            else { std::cerr << "[StaticPatcher]   Failed patching SigCheck (offset 0x" << std::hex << patchFileOffset << " out of bounds)." << std::dec << std::endl; }
        }
        else { std::cerr << "[StaticPatcher]   -> SigCheck pattern NOT FOUND." << std::endl; }

        // --- Apply/Verify ChunkSigCheck Patch ---
        std::optional<size_t> chunkSigOffsetOpt = FindPatternInFileBuffer(fileBuffer, pChunkSigCheck);
        std::optional<size_t> chunkFuncOffsetOpt = FindPatternInFileBuffer(fileBuffer, pChunkSigCheckFunc);
        if (chunkSigOffsetOpt && chunkFuncOffsetOpt) {
            size_t chunkSigOffset = *chunkSigOffsetOpt;
            size_t chunkFuncOffset = *chunkFuncOffsetOpt;
            size_t callInstructionOffset = chunkSigOffset + 0xE; // Offset of E8 call
            size_t operandOffset = callInstructionOffset + 1;   // Offset of relative operand

            std::cout << "[StaticPatcher] Chunk patterns found. Calculating relative offset..." << std::endl;
            std::optional<DWORD> callRVAOpt = FileOffsetToRVA(callInstructionOffset, fileBuffer, pNtHeaders);
            std::optional<DWORD> targetRVAOpt = FileOffsetToRVA(chunkFuncOffset, fileBuffer, pNtHeaders);

            if (callRVAOpt && targetRVAOpt) {
                DWORD callRVA = *callRVAOpt; DWORD targetRVA = *targetRVAOpt;
                int32_t relativeOffset = static_cast<int32_t>(targetRVA - (callRVA + 5)); // Target - (Addr After Call)
                std::cout << "[PE]   CallRVA: 0x" << std::hex << callRVA << ", TargetRVA: 0x" << targetRVA << ", RelOffset: 0x" << relativeOffset << std::dec << std::endl;

                if ((operandOffset + sizeof(int32_t)) <= fileBuffer.size()) { // Check bounds for operand
                    int32_t originalOperand = *reinterpret_cast<int32_t*>(&fileBuffer[operandOffset]);
                    std::cout << "[StaticPatcher]   Original rel offset at 0x" << std::hex << operandOffset << ": 0x" << originalOperand << std::dec << std::endl;
                    bool patchRelativeOk = PatchFileBuffer<int32_t>(fileBuffer, operandOffset, relativeOffset);
                    if (patchRelativeOk) {
                        std::cout << "[StaticPatcher]   Relative offset patch applied. Verifying..." << std::endl;
                        int32_t offsetAfter = *reinterpret_cast<int32_t*>(&fileBuffer[operandOffset]);
                        chunkSigCheckPatchVerified = (offsetAfter == relativeOffset); // Set verification flag
                        if (chunkSigCheckPatchVerified) { std::cout << "[StaticPatcher]   VERIFIED! Relative offset patch successful." << std::endl; }
                        else { std::cerr << "[StaticPatcher]   VERIFICATION FAILED! Relative offset incorrect." << std::endl; }
                    }
                    else { std::cerr << "[StaticPatcher]   Failed patching relative offset (Patch call failed)." << std::endl; }
                }
                else { std::cerr << "[StaticPatcher]   Failed patching relative offset (operand offset 0x" << std::hex << operandOffset << " out of bounds)." << std::dec << std::endl; }
            }
            else { std::cerr << "[PE] Error: Failed to convert one or both file offsets to RVAs for relative patch." << std::endl; }
        }
        else {
            if (!chunkSigOffsetOpt) std::cerr << "[StaticPatcher]   -> ChunkSigCheck pattern NOT FOUND." << std::endl;
            if (!chunkFuncOffsetOpt) std::cerr << "[StaticPatcher]   -> ChunkSigCheckFunc pattern NOT FOUND." << std::endl;
        }
        // Determine overall success: BOTH patches must verify successfully
        patchesAppliedSuccessfully = sigCheckPatchVerified && chunkSigCheckPatchVerified;

    }
    else { std::cerr << "[StaticPatcher] Game type not supported." << std::endl; return false; }


    // --- 4. Write Patched Buffer ---
    if (patchesAppliedSuccessfully) {
        std::cout << "[StaticPatcher] All required patches verified. Writing to: " << patchedExePath << std::endl;
        std::ofstream outFile(patchedExePath, std::ios::binary | std::ios::trunc);
        if (!outFile) { std::cerr << "[StaticPatcher] Error: Cannot open output file: " << patchedExePath << std::endl; return false; }
        if (!outFile.write(reinterpret_cast<const char*>(fileBuffer.data()), static_cast<std::streamsize>(fileBuffer.size()))) {
            std::cerr << "[StaticPatcher] Error: Cannot write patched data to file: " << patchedExePath << std::endl;
            outFile.close(); std::error_code ec; std::filesystem::remove(patchedExePath, ec); return false;
        }
        outFile.close();
        std::cout << "[StaticPatcher] Successfully wrote fully patched executable: " << patchedExePath << std::endl;
        std::cout << "[StaticPatcher] IMPORTANT: Verify differences using a binary comparison tool." << std::endl;
        return true;
    }
    else {
        std::cerr << "[StaticPatcher] One or more required patches FAILED verification. No output file created." << std::endl;
        return false;
    }
} // End CreatePatchedExecutable


// --- DLL Initialization Function ---

bool Initialize()
{
    // 1. Ensure INI exists with defaults
    WriteDefaultConfig();

    // 2. Read INI settings (sets bShowConsole, bAttemptStaticPatch)
    ReadConfig();

    // 3. Create Console if needed
    if (bShowConsole) { CreateConsole(); }

    // 4. Log startup message (to console or debug output)
    std::string msg = "--- UESigPatchTCMPakbypass ASI V" + std::string(ASI_VERSION) + " Initializing ---\n";
    if (bShowConsole) std::cout << msg; else OutputDebugStringA(msg.c_str());
    msg = "[Info] Effective Settings: CreatePatchedExe=" + std::string(bAttemptStaticPatch ? "true" : "false")
        + ", ShowConsole=" + std::string(bShowConsole ? "true" : "false") + "\n";
    if (bShowConsole) std::cout << msg; else OutputDebugStringA(msg.c_str());

    // 5. Handle startup pause
    if (bPauseOnStart) { MessageBoxA(0, "Pausing execution for debugger attachment.", "UESigPatchTCMPakbypass", MB_ICONINFORMATION | MB_OK); }

    // 6. Attempt Static Patching (Conditional)
    bool staticPatchCreated = false;
    if (bAttemptStaticPatch) {
        msg = "[Info] Attempting static patch creation (details -> log file)...\n";
        if (bShowConsole) std::cout << msg; else OutputDebugStringA(msg.c_str());
        if (SetupStaticPatchLogging()) {
            staticPatchCreated = CreatePatchedExecutable();
            RestoreConsoleLogging();
        }
        else {
            msg = "[Error] Failed to set up static patch logging. Aborting static patch attempt.\n";
            if (bShowConsole) std::cerr << msg; else OutputDebugStringA(msg.c_str());
        }
        // Report outcome
        if (staticPatchCreated) {
            msg = "*** Static patched executable created successfully! (See log file for details) ***\n";
            if (bShowConsole) std::cout << msg; else OutputDebugStringA(msg.c_str());
            // Optional MessageBox for non-console users?
            // if (!bShowConsole) MessageBoxA(NULL, "Static patched executable created successfully!", "UESigPatchTCMPakbypass", MB_ICONINFORMATION);
        }
        else {
            msg = "!!! Failed to create static patched executable. (See log file for details) !!!\n";
            if (bShowConsole) std::cerr << msg; else OutputDebugStringA(msg.c_str());
            if (!bShowConsole) MessageBoxA(NULL, "Failed to create static patched executable.", "UESigPatchTCMPakbypass", MB_ICONWARNING);
        }
    }
    else {
        msg = "[Info] Static patch creation skipped (disabled in INI).\n";
        if (bShowConsole) std::cout << msg; else OutputDebugStringA(msg.c_str());
    }

    // 7. Apply runtime patches (Optional)
    bool applyRuntimePatches = true;
    if (applyRuntimePatches) {
        msg = "[RuntimePatcher] Applying runtime patches for current session...\n";
        if (bShowConsole) std::cout << msg; else OutputDebugStringA(msg.c_str());

        std::string currentProcessName = GetProcessName(); // From utils.h/cpp
        eSupportedGames runtimeGameType = GetEnumeratorFromProcessName(currentProcessName);
        const char* pRuntimeSigCheck; const char* pRuntimeChunkSigCheck; const char* pRuntimeChunkSigCheckFunc;

        switch (runtimeGameType) {
        case eGameTcmXbox:
        case eGameTcmSteam:
            msg = "[RuntimePatcher] Detected supported game: " + currentProcessName + "\n";
            if (bShowConsole) std::cout << msg; else OutputDebugStringA(msg.c_str());
            pRuntimeSigCheck = "80 B9 ? ? ? ? 00 49 8B F0 48 8B FA 48 8B D9 75";
            pRuntimeChunkSigCheck = "0F B6 51 ? 48 8B F1 48 8B 0D ? ? ? ? E8 ? ? ? ? C6 46 ? ? 0F AE F8";
            pRuntimeChunkSigCheckFunc = "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC 20 48 8D 59 08 49 63 F9 48 8B F1 49 8B E8 48 8B CB 44 0F B6 F2";
            DisableSignatureCheck(pRuntimeSigCheck); // From patches.h/cpp
            DisableChunkSigCheck(pRuntimeChunkSigCheck, pRuntimeChunkSigCheckFunc); // From patches.h/cpp
            break;
        case eUnsupportedGame:
        default:
            msg = "[RuntimePatcher] Unsupported game (" + currentProcessName + "), runtime patches skipped.\n";
            if (bShowConsole) std::cerr << msg; else OutputDebugStringA(msg.c_str());
            if (!bAttemptStaticPatch || (!staticPatchCreated && bAttemptStaticPatch)) {
                if (!bShowConsole) MessageBoxA(NULL, "Game not supported or static patch failed.\nRuntime patches skipped.", "UESigPatchTCMPakbypass", MB_ICONEXCLAMATION);
            }
            // return false; // Fail DLL load?
            break;
        }
    }
    else {
        msg = "[RuntimePatcher] Runtime patching is disabled.\n";
        if (bShowConsole) std::cout << msg; else OutputDebugStringA(msg.c_str());
    }

    msg = "--- Initialization Complete ---\n";
    if (bShowConsole) std::cout << msg; else OutputDebugStringA(msg.c_str());
    return true; // Success
}


// --- DLL Entry Point ---
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(lpReserved);

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        g_hModule = hModule; // Store module handle IMPORTANT
        // DisableThreadLibraryCalls(hModule); // Optional optimization
        if (!Initialize()) {
            RestoreConsoleLogging(); // Ensure logs restored if Init failed
            return FALSE;
        }
        break;

    case DLL_THREAD_ATTACH: break; // Typically not needed
    case DLL_THREAD_DETACH: break; // Typically not needed

    case DLL_PROCESS_DETACH:
        RestoreConsoleLogging(); // Ensure logs flushed and console restored
        OutputDebugStringA("--- UESigPatchTCMPakbypass Unloading ---\n");
        g_hModule = NULL; // Clear module handle
        break;
    }
    return TRUE; // Signal success
}
