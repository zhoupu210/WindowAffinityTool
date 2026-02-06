/**
 * inject_dll.c - DLL injected into target process
 *
 * Receives commands from main program and calls SetWindowDisplayAffinity
 * Supports both 32-bit and 64-bit versions
 */

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "user32.lib")

#define WDA_NONE               0x00000000
#define WDA_EXCLUDEFROMCAPTURE 0x00000011

typedef struct {
    ULONGLONG hwnd;
    DWORD affinity;
    DWORD padding;
} AffinityCommand;

DWORD WINAPI PipeThreadProc(LPVOID lpParam)
{
    DWORD dwPid = GetCurrentProcessId();
    WCHAR szPipeName[256];
    wsprintfW(szPipeName, L"\\\\.\\pipe\\WindowAffinity_%lu", dwPid);

    HANDLE hPipe = CreateNamedPipeW(
        szPipeName,
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,
        sizeof(AffinityCommand),
        sizeof(AffinityCommand),
        5000,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        return 1;
    }

    if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
        AffinityCommand cmd;
        DWORD dwRead;

        if (ReadFile(hPipe, &cmd, sizeof(cmd), &dwRead, NULL) &&
            dwRead == sizeof(cmd)) {

            HWND hwnd = (HWND)(ULONG_PTR)cmd.hwnd;

            // Always reset to WDA_NONE first to ensure proper state transition
            // This fixes issues when switching between any affinity modes
            SetWindowDisplayAffinity(hwnd, WDA_NONE);
            Sleep(50);

            if (cmd.affinity != WDA_NONE) {
                SetWindowDisplayAffinity(hwnd, cmd.affinity);
            }
        }

        DisconnectNamedPipe(hPipe);
    }

    CloseHandle(hPipe);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, PipeThreadProc, NULL, 0, NULL);
        break;

    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

__declspec(dllexport) BOOL SetAffinity(HWND hwnd, DWORD affinity)
{
    // Always reset to WDA_NONE first to ensure proper state transition
    SetWindowDisplayAffinity(hwnd, WDA_NONE);
    Sleep(50);

    if (affinity == WDA_NONE) {
        return TRUE;
    }
    return SetWindowDisplayAffinity(hwnd, affinity);
}
