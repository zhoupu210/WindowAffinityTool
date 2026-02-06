/**
 * Window Display Affinity Tool
 *
 * Set window's SetWindowDisplayAffinity via drag-and-drop finder
 * Supports: Remote Thread Injection, Shellcode Injection, APC Injection
 * Supports both 32-bit and 64-bit target processes
 */

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <commctrl.h>
#include <dwmapi.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "dwmapi.lib")

#ifndef DWMWA_EXTENDED_FRAME_BOUNDS
#define DWMWA_EXTENDED_FRAME_BOUNDS 9
#endif

#define WINDOW_CLASS_NAME L"WindowAffinityTool"
#define FINDER_CLASS_NAME L"WindowFinder"

#define IDC_FINDER_VISIBLE      1001
#define IDC_FINDER_BLACK        1002
#define IDC_FINDER_TRANSPARENT  1003
#define IDC_RADIO_REMOTE_THREAD 1010
#define IDC_RADIO_SHELLCODE     1011
#define IDC_RADIO_APC           1012
#define IDC_STATIC_INFO         1020
#define IDC_GROUP_METHOD        1030
#define IDC_GROUP_FINDERS       1031

#define WDA_NONE               0x00000000
#define WDA_MONITOR            0x00000001
#define WDA_EXCLUDEFROMCAPTURE 0x00000011

typedef enum {
    INJECT_REMOTE_THREAD = 0,
    INJECT_SHELLCODE,
    INJECT_APC
} InjectMethod;

HINSTANCE g_hInst;
HWND g_hMainWnd;
HWND g_hFinderVisible;
HWND g_hFinderBlack;
HWND g_hFinderTransparent;
HWND g_hStaticInfo;
HCURSOR g_hCursorTarget;
HCURSOR g_hCursorArrow;
HBITMAP g_hBmpFinder;
InjectMethod g_injectMethod = INJECT_REMOTE_THREAD;

BOOL g_bDragging = FALSE;
HWND g_hDragSource = NULL;
DWORD g_dwTargetAffinity = WDA_NONE;

LRESULT CALLBACK MainWndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK FinderWndProc(HWND, UINT, WPARAM, LPARAM);
BOOL RegisterClasses(HINSTANCE);
HWND CreateMainWindow(HINSTANCE);
void CreateControls(HWND);
void DrawFinderIcon(HDC hdc, RECT* pRect, BOOL bPressed);
HWND GetWindowFromPoint(POINT pt);
void HighlightWindow(HWND hwnd, BOOL bHighlight);
BOOL InjectAndSetAffinity(HWND hTargetWnd, DWORD dwAffinity);
BOOL InjectRemoteThread(DWORD dwPid, HWND hTargetWnd, DWORD dwAffinity, BOOL bIsWow64);
BOOL InjectShellcode(DWORD dwPid, HWND hTargetWnd, DWORD dwAffinity, BOOL bIsWow64);
BOOL InjectShellcode32(DWORD dwPid, HWND hTargetWnd, DWORD dwAffinity);
BOOL InjectShellcode64(DWORD dwPid, HWND hTargetWnd, DWORD dwAffinity);
BOOL InjectAPC(DWORD dwPid, HWND hTargetWnd, DWORD dwAffinity, BOOL bIsWow64);
void UpdateInfoText(HWND hTargetWnd);
const WCHAR* GetAffinityName(DWORD dwAffinity);
BOOL EnableDebugPrivilege(void);
BOOL IsProcess64Bit(DWORD dwPid);

BOOL IsProcess64Bit(DWORD dwPid)
{
    BOOL bIsWow64 = FALSE;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPid);
    if (!hProcess) {
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid);
    }
    if (!hProcess) {
        return FALSE;
    }

    typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)
        GetProcAddress(GetModuleHandle(L"kernel32"), "IsWow64Process");

    if (fnIsWow64Process) {
        fnIsWow64Process(hProcess, &bIsWow64);
    }

    CloseHandle(hProcess);

#ifdef _WIN64
    return !bIsWow64;
#else
    return FALSE;
#endif
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                    LPWSTR lpCmdLine, int nCmdShow)
{
    MSG msg;

    g_hInst = hInstance;

    if (lpCmdLine && wcsstr(lpCmdLine, L"/inject")) {
        DWORD dwPid = 0;
        HWND hTargetWnd = NULL;
        DWORD dwAffinity = 0;
        int nMethod = 0;

        if (swscanf(lpCmdLine, L"/inject %lu %p %lu %d",
            &dwPid, &hTargetWnd, &dwAffinity, &nMethod) == 4) {

            EnableDebugPrivilege();

            BOOL bResult = FALSE;
            BOOL bIsWow64 = !IsProcess64Bit(dwPid);

            switch (nMethod) {
            case INJECT_REMOTE_THREAD:
                bResult = InjectRemoteThread(dwPid, hTargetWnd, dwAffinity, bIsWow64);
                break;
            case INJECT_SHELLCODE:
                bResult = InjectShellcode(dwPid, hTargetWnd, dwAffinity, bIsWow64);
                break;
            case INJECT_APC:
                bResult = InjectAPC(dwPid, hTargetWnd, dwAffinity, bIsWow64);
                break;
            }

            return bResult ? 0 : 1;
        }
        return 1;
    }

    EnableDebugPrivilege();

    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icex);

    g_hCursorTarget = LoadCursor(NULL, IDC_CROSS);
    g_hCursorArrow = LoadCursor(NULL, IDC_ARROW);

    if (!RegisterClasses(hInstance)) {
        MessageBox(NULL, L"Failed to register window class!", L"Error", MB_ICONERROR);
        return 1;
    }

    g_hMainWnd = CreateMainWindow(hInstance);
    if (!g_hMainWnd) {
        MessageBox(NULL, L"Failed to create window!", L"Error", MB_ICONERROR);
        return 1;
    }

    ShowWindow(g_hMainWnd, nCmdShow);
    UpdateWindow(g_hMainWnd);

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}

BOOL RegisterClasses(HINSTANCE hInstance)
{
    WNDCLASSEX wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = MainWndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = WINDOW_CLASS_NAME;
    wcex.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

    if (!RegisterClassEx(&wcex)) return FALSE;

    wcex.lpfnWndProc = FinderWndProc;
    wcex.lpszClassName = FINDER_CLASS_NAME;
    wcex.hCursor = LoadCursor(NULL, IDC_CROSS);

    if (!RegisterClassEx(&wcex)) return FALSE;

    return TRUE;
}

HWND CreateMainWindow(HINSTANCE hInstance)
{
#ifdef _WIN64
    const WCHAR* szTitle = L"Window Display Affinity Tool (64-bit)";
#else
    const WCHAR* szTitle = L"Window Display Affinity Tool (32-bit)";
#endif

    HWND hwnd = CreateWindowEx(
        WS_EX_APPWINDOW,
        WINDOW_CLASS_NAME,
        szTitle,
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT,
        400, 350,
        NULL, NULL, hInstance, NULL
    );

    if (hwnd) {
        CreateControls(hwnd);
    }

    return hwnd;
}

void CreateControls(HWND hParent)
{
    CreateWindowEx(0, L"BUTTON", L"Drag to target window",
        WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        10, 10, 370, 100,
        hParent, (HMENU)IDC_GROUP_FINDERS, g_hInst, NULL);

    CreateWindowEx(0, L"STATIC", L"Visible",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        30, 35, 60, 20,
        hParent, NULL, g_hInst, NULL);

    g_hFinderVisible = CreateWindowEx(
        WS_EX_STATICEDGE, FINDER_CLASS_NAME, NULL,
        WS_CHILD | WS_VISIBLE,
        40, 55, 40, 40,
        hParent, (HMENU)IDC_FINDER_VISIBLE, g_hInst, NULL);

    CreateWindowEx(0, L"STATIC", L"Black",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        150, 35, 60, 20,
        hParent, NULL, g_hInst, NULL);

    g_hFinderBlack = CreateWindowEx(
        WS_EX_STATICEDGE, FINDER_CLASS_NAME, NULL,
        WS_CHILD | WS_VISIBLE,
        160, 55, 40, 40,
        hParent, (HMENU)IDC_FINDER_BLACK, g_hInst, NULL);

    CreateWindowEx(0, L"STATIC", L"Hidden",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        270, 35, 60, 20,
        hParent, NULL, g_hInst, NULL);

    g_hFinderTransparent = CreateWindowEx(
        WS_EX_STATICEDGE, FINDER_CLASS_NAME, NULL,
        WS_CHILD | WS_VISIBLE,
        280, 55, 40, 40,
        hParent, (HMENU)IDC_FINDER_TRANSPARENT, g_hInst, NULL);

    CreateWindowEx(0, L"BUTTON", L"Injection Method",
        WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        10, 120, 370, 80,
        hParent, (HMENU)IDC_GROUP_METHOD, g_hInst, NULL);

    CreateWindowEx(0, L"BUTTON", L"Remote Thread",
        WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | WS_GROUP,
        25, 145, 120, 20,
        hParent, (HMENU)IDC_RADIO_REMOTE_THREAD, g_hInst, NULL);

    CreateWindowEx(0, L"BUTTON", L"Shellcode",
        WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
        155, 145, 90, 20,
        hParent, (HMENU)IDC_RADIO_SHELLCODE, g_hInst, NULL);

    CreateWindowEx(0, L"BUTTON", L"APC",
        WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
        255, 145, 100, 20,
        hParent, (HMENU)IDC_RADIO_APC, g_hInst, NULL);

    CheckDlgButton(hParent, IDC_RADIO_SHELLCODE, BST_CHECKED);
    g_injectMethod = INJECT_SHELLCODE;

    CreateWindowEx(0, L"BUTTON", L"Target Window Info",
        WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        10, 210, 370, 100,
        hParent, NULL, g_hInst, NULL);

    g_hStaticInfo = CreateWindowEx(0, L"STATIC",
        L"Drag the icon above to target window...",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        20, 230, 350, 70,
        hParent, (HMENU)IDC_STATIC_INFO, g_hInst, NULL);
}

LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_RADIO_REMOTE_THREAD:
            g_injectMethod = INJECT_REMOTE_THREAD;
            break;
        case IDC_RADIO_SHELLCODE:
            g_injectMethod = INJECT_SHELLCODE;
            break;
        case IDC_RADIO_APC:
            g_injectMethod = INJECT_APC;
            break;
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

LRESULT CALLBACK FinderWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    static HWND s_hLastHighlight = NULL;

    switch (msg) {
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            RECT rect;
            GetClientRect(hwnd, &rect);
            DrawFinderIcon(hdc, &rect, g_bDragging && g_hDragSource == hwnd);
            EndPaint(hwnd, &ps);
        }
        return 0;

    case WM_LBUTTONDOWN:
        {
            g_bDragging = TRUE;
            g_hDragSource = hwnd;
            SetCapture(hwnd);
            SetCursor(g_hCursorTarget);

            int id = GetDlgCtrlID(hwnd);
            if (id == IDC_FINDER_VISIBLE) {
                g_dwTargetAffinity = WDA_NONE;
            } else if (id == IDC_FINDER_BLACK) {
                g_dwTargetAffinity = WDA_MONITOR;
            } else if (id == IDC_FINDER_TRANSPARENT) {
                g_dwTargetAffinity = WDA_EXCLUDEFROMCAPTURE;
            }

            InvalidateRect(hwnd, NULL, TRUE);
        }
        return 0;

    case WM_MOUSEMOVE:
        if (g_bDragging) {
            POINT pt;
            GetCursorPos(&pt);
            HWND hTarget = GetWindowFromPoint(pt);

            if (hTarget != s_hLastHighlight) {
                if (s_hLastHighlight) {
                    HighlightWindow(s_hLastHighlight, FALSE);
                }
                if (hTarget) {
                    HighlightWindow(hTarget, TRUE);
                    UpdateInfoText(hTarget);
                } else {
                    // Clear info when moving out of any window
                    UpdateInfoText(NULL);
                }
                s_hLastHighlight = hTarget;
            }
        }
        return 0;

    case WM_LBUTTONUP:
        if (g_bDragging) {
            g_bDragging = FALSE;
            ReleaseCapture();
            SetCursor(g_hCursorArrow);

            if (s_hLastHighlight) {
                HighlightWindow(s_hLastHighlight, FALSE);
            }

            POINT pt;
            GetCursorPos(&pt);
            HWND hTarget = GetWindowFromPoint(pt);

            // Allow targeting any window including self
            if (hTarget) {

                WCHAR szTitle[256] = {0};
                WCHAR szClass[256] = {0};
                DWORD dwPid = 0;

                GetWindowTextW(hTarget, szTitle, 256);
                GetClassNameW(hTarget, szClass, 256);
                GetWindowThreadProcessId(hTarget, &dwPid);

                BOOL bIs64Bit = IsProcess64Bit(dwPid);
                const WCHAR* szArch = bIs64Bit ? L"64-bit" : L"32-bit";
                BOOL bIsSelf = (hTarget == g_hMainWnd || IsChild(g_hMainWnd, hTarget));

                WCHAR szMsg[1024];
                wsprintfW(szMsg,
                    L"Title: %s\n"
                    L"Class: %s\n"
                    L"PID: %lu (%s)%s\n"
                    L"Handle: 0x%p\n\n"
                    L"Set this window to [%s]?",
                    szTitle[0] ? szTitle : L"(no title)",
                    szClass,
                    dwPid, szArch,
                    bIsSelf ? L" (Self)" : L"",
                    hTarget,
                    GetAffinityName(g_dwTargetAffinity));

                if (MessageBox(g_hMainWnd, szMsg, L"Confirm",
                    MB_YESNO | MB_ICONQUESTION) == IDYES) {

                    BOOL bResult;
                    if (bIsSelf) {
                        // For self, call API directly without injection
                        // Always reset to WDA_NONE first
                        SetWindowDisplayAffinity(g_hMainWnd, WDA_NONE);
                        Sleep(50);
                        if (g_dwTargetAffinity == WDA_NONE) {
                            bResult = TRUE;
                        } else {
                            bResult = SetWindowDisplayAffinity(g_hMainWnd, g_dwTargetAffinity);
                        }
                    } else {
                        bResult = InjectAndSetAffinity(hTarget, g_dwTargetAffinity);
                    }

                    if (bResult) {
                        MessageBox(g_hMainWnd, L"Success!", L"Info", MB_ICONINFORMATION);
                    } else {
                        MessageBox(g_hMainWnd, L"Failed!\nMay need admin rights or target is protected.",
                            L"Error", MB_ICONERROR);
                    }
                }
            }

            s_hLastHighlight = NULL;
            g_hDragSource = NULL;
            InvalidateRect(hwnd, NULL, TRUE);
            // Clear info after release
            UpdateInfoText(NULL);
        }
        return 0;

    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
}

void DrawFinderIcon(HDC hdc, RECT* pRect, BOOL bPressed)
{
    HBRUSH hBrush = CreateSolidBrush(bPressed ? RGB(200, 200, 200) : RGB(255, 255, 255));
    FillRect(hdc, pRect, hBrush);
    DeleteObject(hBrush);

    HPEN hPen = CreatePen(PS_SOLID, 1, RGB(100, 100, 100));
    HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);
    Rectangle(hdc, pRect->left, pRect->top, pRect->right, pRect->bottom);

    int cx = (pRect->left + pRect->right) / 2;
    int cy = (pRect->top + pRect->bottom) / 2;
    int size = min(pRect->right - pRect->left, pRect->bottom - pRect->top) / 2 - 4;

    DeleteObject(hPen);
    hPen = CreatePen(PS_SOLID, 2, RGB(0, 0, 0));
    SelectObject(hdc, hPen);

    HBRUSH hOldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
    Ellipse(hdc, cx - size/2, cy - size/2, cx + size/2, cy + size/2);
    SelectObject(hdc, hOldBrush);

    MoveToEx(hdc, cx - size, cy, NULL);
    LineTo(hdc, cx - size/2 - 2, cy);
    MoveToEx(hdc, cx + size/2 + 2, cy, NULL);
    LineTo(hdc, cx + size, cy);
    MoveToEx(hdc, cx, cy - size, NULL);
    LineTo(hdc, cx, cy - size/2 - 2);
    MoveToEx(hdc, cx, cy + size/2 + 2, NULL);
    LineTo(hdc, cx, cy + size);

    SelectObject(hdc, hOldPen);
    DeleteObject(hPen);
}

HWND GetWindowFromPoint(POINT pt)
{
    HWND hwnd = WindowFromPoint(pt);

    while (hwnd) {
        // Get the root window
        HWND hParent = GetAncestor(hwnd, GA_ROOT);
        if (hParent && hParent != hwnd) {
            hwnd = hParent;
        }
        break;
    }

    return hwnd;
}

void HighlightWindow(HWND hwnd, BOOL bHighlight)
{
    (void)bHighlight;  // Not used - we always draw with XOR to toggle
    if (!hwnd) return;

    // Use screen DC to draw the highlight frame
    HDC hdc = GetDC(NULL);
    if (!hdc) return;

    RECT rect;
    // Try to get the actual visible window bounds (excludes DWM shadow)
    HRESULT hr = DwmGetWindowAttribute(hwnd, DWMWA_EXTENDED_FRAME_BOUNDS, &rect, sizeof(rect));
    if (FAILED(hr)) {
        // Fallback to GetWindowRect if DWM call fails
        GetWindowRect(hwnd, &rect);
    }

    // Use XOR drawing mode - drawing twice will erase the line
    int oldRop = SetROP2(hdc, R2_NOTXORPEN);
    HPEN hPen = CreatePen(PS_SOLID, 3, RGB(255, 0, 0));
    HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);
    HBRUSH hOldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));

    Rectangle(hdc, rect.left, rect.top, rect.right, rect.bottom);

    SelectObject(hdc, hOldBrush);
    SelectObject(hdc, hOldPen);
    DeleteObject(hPen);
    SetROP2(hdc, oldRop);

    ReleaseDC(NULL, hdc);
}

void UpdateInfoText(HWND hTargetWnd)
{
    if (!hTargetWnd) {
        SetWindowText(g_hStaticInfo, L"Drag the icon above to target window...");
        return;
    }

    WCHAR szTitle[256] = {0};
    WCHAR szClass[256] = {0};
    DWORD dwPid = 0;

    GetWindowTextW(hTargetWnd, szTitle, 256);
    GetClassNameW(hTargetWnd, szClass, 256);
    GetWindowThreadProcessId(hTargetWnd, &dwPid);

    BOOL bIs64Bit = IsProcess64Bit(dwPid);

    WCHAR szInfo[512];
    wsprintfW(szInfo,
        L"Title: %s\nClass: %s\nPID: %lu (%s)\nHandle: 0x%p",
        szTitle[0] ? szTitle : L"(no title)",
        szClass, dwPid,
        bIs64Bit ? L"64-bit" : L"32-bit",
        hTargetWnd);

    SetWindowText(g_hStaticInfo, szInfo);
}

const WCHAR* GetAffinityName(DWORD dwAffinity)
{
    switch (dwAffinity) {
    case WDA_NONE:
        return L"Visible";
    case WDA_MONITOR:
        return L"Black";
    case WDA_EXCLUDEFROMCAPTURE:
        return L"Hidden";
    default:
        return L"Unknown";
    }
}

BOOL EnableDebugPrivilege(void)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

BOOL LaunchHelper(DWORD dwPid, HWND hTargetWnd, DWORD dwAffinity, int nMethod, BOOL bNeed32Bit)
{
    WCHAR szExePath[MAX_PATH];
    GetModuleFileName(NULL, szExePath, MAX_PATH);

    WCHAR* pLastSlash = wcsrchr(szExePath, L'\\');
    if (pLastSlash) {
        if (bNeed32Bit) {
            wcscpy(pLastSlash + 1, L"WindowAffinityTool32.exe");
        } else {
            wcscpy(pLastSlash + 1, L"WindowAffinityTool64.exe");
        }
    }

    if (GetFileAttributes(szExePath) == INVALID_FILE_ATTRIBUTES) {
        WCHAR szMsg[512];
        swprintf(szMsg, 512, L"Cannot find %s!\nPlease ensure both 32-bit and 64-bit versions are in the same directory.",
            bNeed32Bit ? L"WindowAffinityTool32.exe" : L"WindowAffinityTool64.exe");
        MessageBox(g_hMainWnd, szMsg, L"Error", MB_ICONERROR);
        return FALSE;
    }

    WCHAR szCmdLine[512];
    swprintf(szCmdLine, 512, L"\"%s\" /inject %lu %p %lu %d",
        szExePath, dwPid, hTargetWnd, dwAffinity, nMethod);

    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (!CreateProcessW(NULL, szCmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        return FALSE;
    }

    WaitForSingleObject(pi.hProcess, 10000);

    DWORD dwExitCode = 1;
    GetExitCodeProcess(pi.hProcess, &dwExitCode);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return (dwExitCode == 0);
}

BOOL InjectAndSetAffinity(HWND hTargetWnd, DWORD dwAffinity)
{
    DWORD dwPid = 0;
    GetWindowThreadProcessId(hTargetWnd, &dwPid);

    if (dwPid == 0) return FALSE;

    BOOL bIs64Bit = IsProcess64Bit(dwPid);

#ifdef _WIN64
    if (!bIs64Bit) {
        return LaunchHelper(dwPid, hTargetWnd, dwAffinity, g_injectMethod, TRUE);
    }
#else
    if (bIs64Bit) {
        return LaunchHelper(dwPid, hTargetWnd, dwAffinity, g_injectMethod, FALSE);
    }
#endif

    BOOL bIsWow64 = !bIs64Bit;

    switch (g_injectMethod) {
    case INJECT_REMOTE_THREAD:
        return InjectRemoteThread(dwPid, hTargetWnd, dwAffinity, bIsWow64);
    case INJECT_SHELLCODE:
        return InjectShellcode(dwPid, hTargetWnd, dwAffinity, bIsWow64);
    case INJECT_APC:
        return InjectAPC(dwPid, hTargetWnd, dwAffinity, bIsWow64);
    default:
        return FALSE;
    }
}

void GetDllPath(WCHAR* szDllPath, BOOL bIsWow64)
{
    GetModuleFileName(NULL, szDllPath, MAX_PATH);
    WCHAR* pLastSlash = wcsrchr(szDllPath, L'\\');
    if (pLastSlash) {
        if (bIsWow64) {
            wcscpy(pLastSlash + 1, L"inject_dll32.dll");
        } else {
            wcscpy(pLastSlash + 1, L"inject_dll64.dll");
        }
    }
}

BOOL InjectRemoteThread(DWORD dwPid, HWND hTargetWnd, DWORD dwAffinity, BOOL bIsWow64)
{
    BOOL bResult = FALSE;
    HANDLE hProcess = NULL;
    LPVOID pRemoteDllPath = NULL;
    HANDLE hThread = NULL;

    WCHAR szDllPath[MAX_PATH];
    GetDllPath(szDllPath, bIsWow64);

    if (GetFileAttributes(szDllPath) == INVALID_FILE_ATTRIBUTES) {
        WCHAR szMsg[512];
        swprintf(szMsg, 512, L"Cannot find %s!\nPlease ensure DLL is in the same directory.",
            bIsWow64 ? L"inject_dll32.dll" : L"inject_dll64.dll");
        MessageBox(g_hMainWnd, szMsg, L"Error", MB_ICONERROR);
        return FALSE;
    }

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
    if (!hProcess) {
        return FALSE;
    }

    size_t nDllPathSize = (wcslen(szDllPath) + 1) * sizeof(WCHAR);
    pRemoteDllPath = VirtualAllocEx(hProcess, NULL, nDllPathSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteDllPath) {
        goto cleanup;
    }

    if (!WriteProcessMemory(hProcess, pRemoteDllPath, szDllPath, nDllPathSize, NULL)) {
        goto cleanup;
    }

    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibraryW =
        (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");

    hThread = CreateRemoteThread(hProcess, NULL, 0,
        pLoadLibraryW, pRemoteDllPath, 0, NULL);
    if (!hThread) {
        goto cleanup;
    }

    WaitForSingleObject(hThread, 5000);

    WCHAR szPipeName[256];
    swprintf(szPipeName, 256, L"\\\\.\\pipe\\WindowAffinity_%lu", dwPid);

    Sleep(100);

    HANDLE hPipe = CreateFile(szPipeName, GENERIC_WRITE, 0, NULL,
        OPEN_EXISTING, 0, NULL);

    if (hPipe != INVALID_HANDLE_VALUE) {
        struct {
            ULONGLONG hwnd;
            DWORD affinity;
            DWORD padding;
        } cmd;
        cmd.hwnd = (ULONGLONG)(ULONG_PTR)hTargetWnd;
        cmd.affinity = dwAffinity;
        cmd.padding = 0;

        DWORD dwWritten;
        WriteFile(hPipe, &cmd, sizeof(cmd), &dwWritten, NULL);
        CloseHandle(hPipe);

        bResult = TRUE;
    }

cleanup:
    if (hThread) CloseHandle(hThread);
    if (pRemoteDllPath) VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
    if (hProcess) CloseHandle(hProcess);

    return bResult;
}

BOOL InjectShellcode(DWORD dwPid, HWND hTargetWnd, DWORD dwAffinity, BOOL bIsWow64)
{
    // Always reset to WDA_NONE first to ensure proper state transition
    // This fixes issues when switching between any affinity modes
    if (bIsWow64) {
        InjectShellcode32(dwPid, hTargetWnd, WDA_NONE);
    } else {
        InjectShellcode64(dwPid, hTargetWnd, WDA_NONE);
    }
    Sleep(50);  // Small delay for DWM to process

    // If target is WDA_NONE, we're already done
    if (dwAffinity == WDA_NONE) {
        return TRUE;
    }

    if (bIsWow64) {
        return InjectShellcode32(dwPid, hTargetWnd, dwAffinity);
    } else {
        return InjectShellcode64(dwPid, hTargetWnd, dwAffinity);
    }
}

BOOL InjectShellcode32(DWORD dwPid, HWND hTargetWnd, DWORD dwAffinity)
{
    BOOL bResult = FALSE;
    HANDLE hProcess = NULL;
    LPVOID pRemoteMem = NULL;
    HANDLE hThread = NULL;

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
    if (!hProcess) {
        return FALSE;
    }

    HMODULE hUser32 = GetModuleHandle(L"user32.dll");
    if (!hUser32) {
        hUser32 = LoadLibrary(L"user32.dll");
    }

    FARPROC pSetWindowDisplayAffinity = GetProcAddress(hUser32, "SetWindowDisplayAffinity");
    if (!pSetWindowDisplayAffinity) {
        goto cleanup;
    }

    BYTE shellcode[] = {
        0xE8, 0x00, 0x00, 0x00, 0x00,
        0x58,
        0x83, 0xC0, 0x1A,
        0xFF, 0x70, 0x04,
        0xFF, 0x30,
        0xFF, 0x50, 0x08,
        0xC3,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    *(DWORD*)(&shellcode[32]) = (DWORD)(ULONG_PTR)hTargetWnd;
    *(DWORD*)(&shellcode[36]) = dwAffinity;
    *(DWORD*)(&shellcode[40]) = (DWORD)(ULONG_PTR)pSetWindowDisplayAffinity;

    pRemoteMem = VirtualAllocEx(hProcess, NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteMem) {
        goto cleanup;
    }

    if (!WriteProcessMemory(hProcess, pRemoteMem, shellcode, sizeof(shellcode), NULL)) {
        goto cleanup;
    }

    FlushInstructionCache(hProcess, pRemoteMem, sizeof(shellcode));

    hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pRemoteMem, NULL, 0, NULL);
    if (!hThread) {
        goto cleanup;
    }

    WaitForSingleObject(hThread, 5000);
    bResult = TRUE;

cleanup:
    if (hThread) CloseHandle(hThread);
    if (pRemoteMem) VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    if (hProcess) CloseHandle(hProcess);

    return bResult;
}

BOOL InjectShellcode64(DWORD dwPid, HWND hTargetWnd, DWORD dwAffinity)
{
    BOOL bResult = FALSE;
    HANDLE hProcess = NULL;
    LPVOID pRemoteMem = NULL;
    HANDLE hThread = NULL;

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
    if (!hProcess) {
        return FALSE;
    }

    HMODULE hUser32 = GetModuleHandle(L"user32.dll");
    if (!hUser32) {
        hUser32 = LoadLibrary(L"user32.dll");
    }

    FARPROC pSetWindowDisplayAffinity = GetProcAddress(hUser32, "SetWindowDisplayAffinity");
    if (!pSetWindowDisplayAffinity) {
        goto cleanup;
    }

    BYTE shellcode[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0x8D, 0x05, 0x35, 0x00, 0x00, 0x00,
        0x48, 0x8B, 0x08,
        0x8B, 0x50, 0x08,
        0x48, 0x8B, 0x40, 0x10,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x28,
        0xC3,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    *(ULONGLONG*)(&shellcode[64]) = (ULONGLONG)(ULONG_PTR)hTargetWnd;
    *(DWORD*)(&shellcode[72]) = dwAffinity;
    *(ULONGLONG*)(&shellcode[80]) = (ULONGLONG)(ULONG_PTR)pSetWindowDisplayAffinity;

    pRemoteMem = VirtualAllocEx(hProcess, NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteMem) {
        goto cleanup;
    }

    if (!WriteProcessMemory(hProcess, pRemoteMem, shellcode, sizeof(shellcode), NULL)) {
        goto cleanup;
    }

    FlushInstructionCache(hProcess, pRemoteMem, sizeof(shellcode));

    hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pRemoteMem, NULL, 0, NULL);
    if (!hThread) {
        goto cleanup;
    }

    WaitForSingleObject(hThread, 5000);
    bResult = TRUE;

cleanup:
    if (hThread) CloseHandle(hThread);
    if (pRemoteMem) VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    if (hProcess) CloseHandle(hProcess);

    return bResult;
}

BOOL InjectAPC(DWORD dwPid, HWND hTargetWnd, DWORD dwAffinity, BOOL bIsWow64)
{
    BOOL bResult = FALSE;
    HANDLE hProcess = NULL;
    HANDLE hSnapshot = NULL;
    LPVOID pRemoteDllPath = NULL;

    WCHAR szDllPath[MAX_PATH];
    GetDllPath(szDllPath, bIsWow64);

    if (GetFileAttributes(szDllPath) == INVALID_FILE_ATTRIBUTES) {
        WCHAR szMsg[512];
        swprintf(szMsg, 512, L"Cannot find %s!\nPlease ensure DLL is in the same directory.",
            bIsWow64 ? L"inject_dll32.dll" : L"inject_dll64.dll");
        MessageBox(g_hMainWnd, szMsg, L"Error", MB_ICONERROR);
        return FALSE;
    }

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
    if (!hProcess) {
        return FALSE;
    }

    size_t nDllPathSize = (wcslen(szDllPath) + 1) * sizeof(WCHAR);
    pRemoteDllPath = VirtualAllocEx(hProcess, NULL, nDllPathSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteDllPath) {
        goto cleanup;
    }

    if (!WriteProcessMemory(hProcess, pRemoteDllPath, szDllPath, nDllPathSize, NULL)) {
        goto cleanup;
    }

    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    PAPCFUNC pLoadLibraryW = (PAPCFUNC)GetProcAddress(hKernel32, "LoadLibraryW");

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        goto cleanup;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    int nQueued = 0;
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == dwPid) {
                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                    FALSE, te32.th32ThreadID);
                if (hThread) {
                    if (QueueUserAPC(pLoadLibraryW, hThread, (ULONG_PTR)pRemoteDllPath)) {
                        nQueued++;
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    if (nQueued > 0) {
        Sleep(500);

        WCHAR szPipeName[256];
        swprintf(szPipeName, 256, L"\\\\.\\pipe\\WindowAffinity_%lu", dwPid);

        HANDLE hPipe = CreateFile(szPipeName, GENERIC_WRITE, 0, NULL,
            OPEN_EXISTING, 0, NULL);

        if (hPipe != INVALID_HANDLE_VALUE) {
            struct {
                ULONGLONG hwnd;
                DWORD affinity;
                DWORD padding;
            } cmd;
            cmd.hwnd = (ULONGLONG)(ULONG_PTR)hTargetWnd;
            cmd.affinity = dwAffinity;
            cmd.padding = 0;

            DWORD dwWritten;
            WriteFile(hPipe, &cmd, sizeof(cmd), &dwWritten, NULL);
            CloseHandle(hPipe);

            bResult = TRUE;
        }
    }

cleanup:
    if (hSnapshot && hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
    if (!bResult && pRemoteDllPath) {
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
    }
    if (hProcess) CloseHandle(hProcess);

    return bResult;
}
