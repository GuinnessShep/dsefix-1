# dsefix
Windows x64 Driver Signature Enforcement Overrider


In windows 10 1903, g_CiOptions value is not 0x6 but 0x2006.
I changed shellcode using bit operation so no more bsod when DSE re-enabled.

before
/*
**  Disable DSE (Vista and above)
**  xor rax, rax
**  ret
*/
const unsigned char scDisable[] = {
    0x48, 0x31, 0xc0, 0xc3
};

/*
**  Enable DSE (W8 and above)
**  xor rax, rax
**  mov al, 6
**  ret
*/
const unsigned char scEnable8Plus[] = {
    0x48, 0x31, 0xc0, 0xb0, 0x06, 0xc3
};


after
/*
**  Disable DSE (W7 also has ci.dll)
**  mov eax,[g_CiAddress]
**  and al,~6
**  ret
*/
unsigned char scDisable[] = {
	0xA1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0xF9, 0xC3
};

/*
**  Enable DSE
**  mov eax,[g_CiAddress]
**  or al,6
**  ret
*/
unsigned char scEnable[] = {
	0xA1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x06, 0xC3
};
