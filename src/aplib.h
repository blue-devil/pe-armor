#ifndef APLIB_H
#define APLIB_H
#include <windows.h>
DWORD __cdecl aP_pack(const void *src, void *dst, DWORD len, void *workmem,
                      int (__cdecl *cb)(unsigned int, unsigned int), void *cbparam);
DWORD __cdecl aP_workmem_size(DWORD len);
DWORD __cdecl aP_max_packed_size(DWORD len);
#endif
