/* Public copied-artifact controls. Never writes to a reviewed source image. */
#include "image_pin.h"
#include <stdio.h>
#include <wchar.h>

static unsigned child_completed, write_denied, delete_denied, rename_denied;
static DWORD parent_rename_error;

static int child(const wchar_t* executable, const wchar_t* image) {
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    wchar_t command[2 * PIN_PATH + 16];
    DWORD wait, code = 99;
    int ok;
    startup.cb = sizeof(startup);
    if (swprintf_s(command, sizeof(command)/sizeof(command[0]), L"\"%ls\" \"%ls\"", executable, image) < 0) { return 0; }
    if (!CreateProcessW(executable, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process)) { return 0; }
    wait = WaitForSingleObject(process.hProcess, 30000);
    if (wait != WAIT_OBJECT_0) {
        /* Only this explicitly created diagnostic child is terminated. */
        (void)TerminateProcess(process.hProcess, 99);
        (void)WaitForSingleObject(process.hProcess, 5000);
    }
    ok = wait == WAIT_OBJECT_0 && GetExitCodeProcess(process.hProcess, &code) && code == 0;
    if (!CloseHandle(process.hThread)) { ok = 0; }
    if (!CloseHandle(process.hProcess)) { ok = 0; }
    return ok;
}

static unsigned campaign(const wchar_t* image, const wchar_t* changed,
                         const wchar_t* executable, const wchar_t* moved_parent) {
    PINNED_IMAGE pin;
    HANDLE handle;
    wchar_t parent[PIN_PATH], moved[PIN_PATH];
    wchar_t* slash;
    DWORD error;
    if (ImagePinOpen(&pin, changed)) { (void)ImagePinClose(&pin); return 10; }
    if (pin.count || pin.file != INVALID_HANDLE_VALUE) { return 12; }
    handle = CreateFileW(image, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE) { return 13; }
    if (ImagePinOpen(&pin, image)) { (void)ImagePinClose(&pin); CloseHandle(handle); return 11; }
    if (!CloseHandle(handle) || pin.count || pin.file != INVALID_HANDLE_VALUE) { return 14; }
    if (!ImagePinOpen(&pin, image)) { return 15; }
    handle = CreateFileW(image, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE) { (void)ImagePinClose(&pin); return 16; }
    if (!CloseHandle(handle)) { (void)ImagePinClose(&pin); return 17; }
    handle = CreateFileW(image, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    error = GetLastError();
    if (handle != INVALID_HANDLE_VALUE) { CloseHandle(handle); (void)ImagePinClose(&pin); return 18; }
    if (error != ERROR_SHARING_VIOLATION) { (void)ImagePinClose(&pin); return 19; }
    write_denied = 1;
    handle = CreateFileW(image, DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    error = GetLastError();
    if (handle != INVALID_HANDLE_VALUE) { CloseHandle(handle); (void)ImagePinClose(&pin); return 20; }
    if (error != ERROR_SHARING_VIOLATION) { (void)ImagePinClose(&pin); return 21; }
    delete_denied = 1;
    if (swprintf_s(moved, PIN_PATH, L"%ls.moved", image) < 0) { (void)ImagePinClose(&pin); return 22; }
    if (MoveFileExW(image, moved, 0)) {
        (void)MoveFileExW(moved, image, 0); (void)ImagePinClose(&pin); return 23;
    }
    if (GetLastError() != ERROR_SHARING_VIOLATION) { (void)ImagePinClose(&pin); return 24; }
    rename_denied = 1;
    if (wcscpy_s(parent, PIN_PATH, image)) { (void)ImagePinClose(&pin); return 25; }
    slash = wcsrchr(parent, L'\\');
    if (!slash || slash == parent + 2) { (void)ImagePinClose(&pin); return 26; }
    *slash = 0;
    if (MoveFileExW(parent, moved_parent, 0)) {
        (void)MoveFileExW(moved_parent, parent, 0); (void)ImagePinClose(&pin); return 27;
    }
    parent_rename_error = GetLastError();
    if (parent_rename_error != ERROR_SHARING_VIOLATION && parent_rename_error != ERROR_ACCESS_DENIED) {
        (void)ImagePinClose(&pin); return 28;
    }
    if (!child(executable, image)) { (void)ImagePinClose(&pin); return 29; }
    child_completed = 1;
    if (!ImagePinClose(&pin) || pin.count || pin.file != INVALID_HANDLE_VALUE) { return 30; }
    /* Positive controls: operations work after release, not merely ACL denial. */
    if (!MoveFileExW(parent, moved_parent, 0)) { return 33; }
    if (!MoveFileExW(moved_parent, parent, 0)) { return 34; }
    if (!MoveFileExW(image, moved, 0)) { return 35; }
    if (!MoveFileExW(moved, image, 0)) { return 36; }
    handle = CreateFileW(image, DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE) { return 37; }
    if (!CloseHandle(handle)) { return 38; }
    handle = CreateFileW(image, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE) { return 31; }
    if (!CloseHandle(handle)) { return 32; }
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    unsigned result;
    if (argc != 5) { return 99; }
    result = campaign(argv[1], argv[2], argv[3], argv[4]);
    printf("{\"kind\":\"image-pin\",\"result\":%u,\"child_completed\":%u,"
           "\"write_denied\":%u,\"delete_denied\":%u,\"rename_denied\":%u,\"parent_rename_error\":%lu}\n",
           result, child_completed, write_denied, delete_denied, rename_denied, parent_rename_error);
    return result ? 97 : 0;
}
