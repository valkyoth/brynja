/* Research platform glue only. Hashing stays in first-party Rust. */
#include "image_pin.h"
#include <wchar.h>
#include <intrin.h>

__declspec(noreturn) void ProbeImageAbort(void) { __fastfail(FAST_FAIL_FATAL_APP_EXIT); }

int ImagePinClose(PINNED_IMAGE* pin) {
    int ok = 1;
    if (pin->file != INVALID_HANDLE_VALUE) {
        if (CloseHandle(pin->file)) { pin->file = INVALID_HANDLE_VALUE; }
        else { ok = 0; }
    }
    while (pin->count) {
        if (!CloseHandle(pin->parents[pin->count - 1])) { return 0; }
        pin->count -= 1;
    }
    return ok;
}

static int normal_path(const wchar_t* path, size_t* length) {
    size_t n = 0, start = 3, i;
    if (!path) { return 0; }
    while (n < PIN_PATH && path[n]) { ++n; }
    if (n < 4 || n == PIN_PATH || path[0] < L'A' || path[0] > L'Z'
        || path[1] != L':' || path[2] != L'\\') { return 0; }
    for (i = 3; i <= n; ++i) {
        wchar_t c = path[i];
        if (c == 0 || c == L'\\') {
            if (i == start || path[i-1] == L'.' || path[i-1] == L' ') { return 0; }
            start = i + 1;
        } else if (c < 32 || c == L':' || c == L'/' || c == L'"' || c == L'<'
                   || c == L'>' || c == L'|' || c == L'?' || c == L'*') { return 0; }
    }
    *length = n;
    return 1;
}

static int directory(PINNED_IMAGE* pin, const wchar_t* path) {
    BY_HANDLE_FILE_INFORMATION info;
    HANDLE h;
    if (pin->count == PIN_PARENTS) { return 0; }
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (h == INVALID_HANDLE_VALUE) { return 0; }
    pin->parents[pin->count++] = h;
    return GetFileType(h) == FILE_TYPE_DISK && GetFileInformationByHandle(h, &info)
        && (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
            == FILE_ATTRIBUTE_DIRECTORY;
}

int ImagePinOpen(PINNED_IMAGE* pin, const wchar_t* path) {
    wchar_t current[PIN_PATH];
    BY_HANDLE_FILE_INFORMATION info;
    LARGE_INTEGER length;
    unsigned char* bytes = NULL;
    unsigned char extra;
    size_t size, i;
    DWORD read = 0, tail = 0, sharing = FILE_SHARE_READ;
    int ok = 0;
    pin->file = INVALID_HANDLE_VALUE; pin->count = 0;
    if (!normal_path(path, &size)) { return 0; }
    wmemcpy(current, path, size + 1);
    current[3] = 0;
    if (!directory(pin, current)) { goto done; }
    current[3] = path[3];
    for (i = 3; i < size; ++i) {
        if (current[i] == L'\\') {
            current[i] = 0;
            if (!directory(pin, current)) { goto done; }
            current[i] = L'\\';
        }
    }
#ifdef BRYNJA_PIN_ALLOW_WRITE
    sharing |= FILE_SHARE_WRITE;
#endif
    pin->file = CreateFileW(path, GENERIC_READ, sharing, NULL, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (pin->file == INVALID_HANDLE_VALUE || GetFileType(pin->file) != FILE_TYPE_DISK
        || !GetFileInformationByHandle(pin->file, &info)
        || (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))
        || !GetFileSizeEx(pin->file, &length) || length.QuadPart < 512
        || length.QuadPart > 16 * 1024 * 1024) { goto done; }
    bytes = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)length.QuadPart);
    if (!bytes || !ReadFile(pin->file, bytes, (DWORD)length.QuadPart, &read, NULL)
        || read != (DWORD)length.QuadPart || !ReadFile(pin->file, &extra, 1, &tail, NULL)
        || tail != 0) { goto done; }
#ifdef BRYNJA_PIN_SKIP_HASH
    ok = 1;
#else
    ok = ProbeImageCheck(bytes, read) == 1;
#endif
done:
    if (bytes && !HeapFree(GetProcessHeap(), 0, bytes)) { ok = 0; }
    if (!ok) { (void)ImagePinClose(pin); }
    return ok;
}
