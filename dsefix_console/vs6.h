#pragma once
#include <windows.h>

/*
VIsual Studio 6.0 Setup

VC++ Directory - Include directory
C:\Program Files\Microsoft Platform SDK for Windows Server 2003 R2\Include;
C:\Program Files\Microsoft Platform SDK for Windows Server 2003 R2\Include\crt;
C:\Program Files\Microsoft Platform SDK for Windows Server 2003 R2\Include\crt\sys;
C:\Program Files\Microsoft Platform SDK for Windows Server 2003 R2\Include\mfc;
C:\Program Files\Microsoft Platform SDK for Windows Server 2003 R2\Include\atl

VC++ Directory - Library directory
x64
C:\Program Files\Microsoft Platform SDK for Windows Server 2003 R2\Lib\AMD64;
C:\Program Files\Microsoft Platform SDK for Windows Server 2003 R2\Lib\AMD64\atlmfc;
C:\Program Files\Microsoft Platform SDK for Windows Server 2003 R2\Lib
x86
C:\Program Files\Microsoft Platform SDK for Windows Server 2003 R2\Lib;
C:\Program Files\Microsoft Platform SDK for Windows Server 2003 R2\Lib\MFC
*/

//C++, Code Generation, /GS-
//C++, Code Generation, Basic Runtime Check, default
//C++, Optimization, remove /GL
//Linker, /SAFESEH:NO (x86)

//for C++ exception handling
//C++, Runtime Library, /MD (Multi Thread DLL)
//Maybe, There's no "msvcrtd.dll". So use "msvcrt.dll".
//when using static library, try-catch does not work.

#ifdef _WIN64
#pragma comment(lib, "vs6port64.lib")
#else
#pragma comment(lib, "vs6port86.lib")
#endif