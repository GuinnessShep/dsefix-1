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
x86
C:\Program Files\Microsoft Platform SDK for Windows Server 2003 R2\Lib;
C:\Program Files\Microsoft Platform SDK for Windows Server 2003 R2\Lib\MFC
*/

//Maybe, There's no "msvcrtd.dll". So use "msvcrt.dll".
//when using static library, try-catch does not work.

//C++, Runtime Library, /MD (Multi Thread DLL)
//C++, Code Generation, /GS-
//C++, Code Generation, Basic Runtime Check, default
//C++, Optimization, remove /GL
//Linker, Advanced, /SAFESEH:NO (x86)
//Linker, Debugging, /MAP

__declspec(dllimport) void terminate();
extern "C" __declspec(dllimport) void __CxxFrameHandler();
#ifdef _WIN64
void __std_terminate() { terminate(); }
extern "C" void __CxxFrameHandler3() { __CxxFrameHandler(); }
#else
__declspec(naked) void __std_terminate() { __asm jmp terminate }
extern "C" __declspec(naked) void __CxxFrameHandler3() { __asm jmp __CxxFrameHandler }
#endif