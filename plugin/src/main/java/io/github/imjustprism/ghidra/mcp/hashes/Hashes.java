package io.github.imjustprism.ghidra.mcp.hashes;

import java.util.Set;

public final class Hashes {

    private Hashes() {}

    public static final Set<String> ANTI_DEBUG_APIS = Set.of(
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "NtQuerySystemInformation", "NtSetInformationThread", "NtGlobalFlag",
        "OutputDebugStringA", "OutputDebugStringW", "DebugActiveProcess",
        "FindWindowA", "FindWindowW", "FindWindowExA", "FindWindowExW",
        "GetTickCount", "GetTickCount64", "QueryPerformanceCounter", "timeGetTime",
        "RDTSC", "ZwQueryInformationProcess", "DbgBreakPoint", "DbgUiRemoteBreakin",
        "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
        "NtCreateThreadEx", "SetUnhandledExceptionFilter", "UnhandledExceptionFilter",
        "VirtualProtect", "VirtualAlloc", "WriteProcessMemory", "ReadProcessMemory",
        "ptrace", "prctl", "getppid"
    );

    public static final String[] COMMON_APIS = {
        "ExitProcess","TerminateProcess","ExitThread","CreateProcessA","CreateProcessW",
        "OpenProcess","GetCurrentProcess","GetCurrentProcessId","GetCurrentThreadId",
        "GetProcessHeap","HeapAlloc","HeapFree","HeapReAlloc","HeapCreate","HeapDestroy",
        "VirtualAlloc","VirtualAllocEx","VirtualFree","VirtualProtect","VirtualProtectEx",
        "VirtualQuery","VirtualQueryEx","ReadProcessMemory","WriteProcessMemory",
        "CreateFileA","CreateFileW","ReadFile","WriteFile","CloseHandle","DeleteFileA","DeleteFileW",
        "MoveFileA","MoveFileW","CopyFileA","CopyFileW","GetFileSize","GetFileSizeEx",
        "GetFileAttributesA","GetFileAttributesW","SetFilePointer","SetFilePointerEx",
        "FindFirstFileA","FindFirstFileW","FindNextFileA","FindNextFileW","FindClose",
        "CreateDirectoryA","CreateDirectoryW","RemoveDirectoryA","RemoveDirectoryW",
        "LoadLibraryA","LoadLibraryW","LoadLibraryExA","LoadLibraryExW","FreeLibrary",
        "GetProcAddress","GetModuleHandleA","GetModuleHandleW","GetModuleFileNameA","GetModuleFileNameW",
        "CreateThread","CreateRemoteThread","ResumeThread","SuspendThread","TerminateThread",
        "WaitForSingleObject","WaitForMultipleObjects","Sleep","SleepEx",
        "CreateMutexA","CreateMutexW","ReleaseMutex","CreateEventA","CreateEventW","SetEvent","ResetEvent",
        "CreateSemaphoreA","CreateSemaphoreW","ReleaseSemaphore",
        "EnterCriticalSection","LeaveCriticalSection","InitializeCriticalSection","DeleteCriticalSection",
        "GetLastError","SetLastError","FormatMessageA","FormatMessageW",
        "GetTickCount","GetTickCount64","QueryPerformanceCounter","QueryPerformanceFrequency",
        "GetSystemTime","GetLocalTime","GetSystemTimeAsFileTime","GetFileTime","SetFileTime",
        "IsDebuggerPresent","CheckRemoteDebuggerPresent","OutputDebugStringA","OutputDebugStringW",
        "SetUnhandledExceptionFilter","UnhandledExceptionFilter","AddVectoredExceptionHandler",
        "RtlAddVectoredExceptionHandler","RtlRandomEx","RtlCompareMemory","RtlMoveMemory","RtlZeroMemory",
        "NtQueryInformationProcess","NtQuerySystemInformation","NtSetInformationThread",
        "NtCreateFile","NtReadFile","NtWriteFile","NtClose","NtCreateThreadEx","NtOpenProcess",
        "NtAllocateVirtualMemory","NtProtectVirtualMemory","NtReadVirtualMemory","NtWriteVirtualMemory",
        "NtDelayExecution","NtSetContextThread","NtGetContextThread",
        "DbgBreakPoint","DbgUiRemoteBreakin","DbgPrint","ZwQueryInformationProcess",
        "GetComputerNameA","GetComputerNameW","GetComputerNameExA","GetComputerNameExW",
        "GetUserNameA","GetUserNameW","GetCommandLineA","GetCommandLineW",
        "GetCurrentDirectoryA","GetCurrentDirectoryW","GetSystemDirectoryA","GetSystemDirectoryW",
        "GetWindowsDirectoryA","GetWindowsDirectoryW","GetTempPathA","GetTempPathW","GetTempFileNameA",
        "GetEnvironmentVariableA","GetEnvironmentVariableW","SetEnvironmentVariableA","SetEnvironmentVariableW",
        "GetStartupInfoA","GetStartupInfoW","GetStdHandle","SetStdHandle",
        "ReadConsoleA","ReadConsoleW","WriteConsoleA","WriteConsoleW","SetConsoleTitleA","SetConsoleTitleW",
        "GetConsoleMode","SetConsoleMode","AllocConsole","FreeConsole","AttachConsole",
        "MessageBoxA","MessageBoxW","MessageBoxExA","MessageBoxExW",
        "FindWindowA","FindWindowW","FindWindowExA","FindWindowExW",
        "GetWindowTextA","GetWindowTextW","SetWindowTextA","SetWindowTextW",
        "ShellExecuteA","ShellExecuteW","ShellExecuteExA","ShellExecuteExW","WinExec",
        "RegOpenKeyA","RegOpenKeyW","RegOpenKeyExA","RegOpenKeyExW","RegCloseKey",
        "RegQueryValueA","RegQueryValueW","RegQueryValueExA","RegQueryValueExW",
        "RegSetValueA","RegSetValueW","RegSetValueExA","RegSetValueExW","RegCreateKeyExA","RegCreateKeyExW",
        "CryptAcquireContextA","CryptAcquireContextW","CryptReleaseContext","CryptCreateHash",
        "CryptHashData","CryptDeriveKey","CryptEncrypt","CryptDecrypt","CryptDestroyHash","CryptDestroyKey",
        "CryptGenRandom","CryptGetHashParam","CryptImportKey","CryptExportKey",
        "BCryptOpenAlgorithmProvider","BCryptCloseAlgorithmProvider","BCryptGenRandom","BCryptHash",
        "WSAStartup","WSACleanup","socket","connect","bind","listen","accept","send","recv",
        "closesocket","gethostbyname","gethostbyaddr","getaddrinfo","inet_addr","inet_ntoa",
        "CreateToolhelp32Snapshot","Process32First","Process32Next","Module32First","Module32Next",
        "Thread32First","Thread32Next","EnumProcesses","EnumProcessModules","GetModuleBaseNameA",
        "IsWow64Process","Wow64DisableWow64FsRedirection","Wow64RevertWow64FsRedirection"
    };

    public static int fnv1a(String s, boolean upper) {
        int h = 0x811c9dc5;
        for (int i = 0; i < s.length(); i++) {
            int c = s.charAt(i);
            if (upper && c >= 'a' && c <= 'z') c -= 0x20;
            h = (h ^ c) * 0x01000193;
        }
        return h;
    }

    public static int djb2(String s) {
        int h = 5381;
        for (int i = 0; i < s.length(); i++) h = (h * 33) + s.charAt(i);
        return h;
    }

    public static int crc32(String s) {
        var crc = new java.util.zip.CRC32();
        crc.update(s.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        return (int) crc.getValue();
    }
}
