/* Public artifact file-lifetime experiment; not signature/identity verification. */
#ifndef BRYNJA_IMAGE_PIN_H
#define BRYNJA_IMAGE_PIN_H
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#define PIN_PATH 1024
#define PIN_PARENTS 64
typedef struct {
    HANDLE file, parents[PIN_PARENTS];
    unsigned count;
} PINNED_IMAGE;
int ImagePinOpen(PINNED_IMAGE*, const wchar_t*);
int ImagePinClose(PINNED_IMAGE*);
int ProbeImageCheck(const unsigned char*, size_t);
#endif
