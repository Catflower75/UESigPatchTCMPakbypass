#include "pch.h"

#include "patches.h"
#include "utils.h"
#include <string>

constexpr const char* ASI_VERSION = "1.2.0";

bool bPauseOnStart = false;
bool bShowConsole = false;

enum eSupportedGames {
	eGameTcmXbox,
	eGameTcmSteam,
	eUnsupportedGame
};

eSupportedGames GetEnumeratorFromProcessName(std::string const& sProcessName) {
	if (sProcessName == "BBQClient-WinGDK-Shipping.exe") return eGameTcmXbox;
	if (sProcessName == "BBQClient-Win64-Shipping.exe") return eGameTcmSteam;
	return eUnsupportedGame;
}

void CreateConsole()
{
	FreeConsole();
	AllocConsole();

	FILE* fNull;
	freopen_s(&fNull, "CONOUT$", "w", stdout);
	freopen_s(&fNull, "CONOUT$", "w", stderr);

	std::string consoleName = "UESigPatchTCMPakbypass Console";
	HANDLE Console = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD dwMode = 0;
	dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;

	SetConsoleTitleA(consoleName.c_str());
	GetConsoleMode(Console, &dwMode);
	SetConsoleMode(Console, dwMode);

	std::streambuf* coutbuf = std::cout.rdbuf();
	std::cout.rdbuf(coutbuf);
}

bool Initialize()
{
	const char* pSigCheck;
	const char* pSigWarn;
	const char* pChunkSigCheck;
	const char* pChunkSigCheckFunc;
	const char* pTOCCheck;
	const char* pTOCCompare;

	if (bPauseOnStart) MessageBoxA(0, "Pausing execution, attach your debugger now.", "UESigPatch", MB_ICONINFORMATION);
	if (bShowConsole) CreateConsole();

	switch (GetEnumeratorFromProcessName(GetProcessName())) {
       case eGameTcmXbox:
			pSigCheck = "80 B9 ? ? ? ? 00 49 8B F0 48 8B FA 48 8B D9 75";
			pChunkSigCheck = "0F B6 51 ? 48 8B F1 48 8B 0D ? ? ? ? E8 ? ? ? ? C6 46 ? ? 0F AE F8";
			pChunkSigCheckFunc = "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC 20 48 8D 59 08 49 63 F9 48 8B F1 49 8B E8 48 8B CB 44 0F B6 F2";

			DisableSignatureCheck(pSigCheck);
			DisableChunkSigCheck(pChunkSigCheck, pChunkSigCheckFunc);

			break;

	   case eGameTcmSteam:
		   pSigCheck = "80 B9 ? ? ? ? 00 49 8B F0 48 8B FA 48 8B D9 75";
		   pChunkSigCheck = "0F B6 51 ? 48 8B F1 48 8B 0D ? ? ? ? E8 ? ? ? ? C6 46 ? ? 0F AE F8";
		   pChunkSigCheckFunc = "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC 20 48 8D 59 08 49 63 F9 48 8B F1 49 8B E8 48 8B CB 44 0F B6 F2";

		   DisableSignatureCheck(pSigCheck);
		   DisableChunkSigCheck(pChunkSigCheck, pChunkSigCheckFunc);

		   break;

		case eUnsupportedGame:
		default:
			MessageBoxA(NULL, "This version of UESigPatchTCMPakbypass is not compatible with the currently loading game, all patches have been skipped.", "UESigPatchTCMPakbypass", MB_ICONEXCLAMATION);
			return false;
	}

	return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    switch (reason)
    {
		case DLL_PROCESS_ATTACH:
			if (!Initialize())
				return false;
    }
    return true;
}
