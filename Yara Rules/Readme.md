# Suspicious YARA Rule

This YARA rule detects Windows PE files containing XOR-encrypted shellcode and common WinAPI calls.

## Features
- Detects NOP sleds and XOR decryption stubs
- Checks imports from kernel32.dll and kernelbase.dll
- Falls back on string detection for VirtualAlloc, CreateThread, WriteProcessMemory, etc.

## Usage
```bash
yara64.exe -s Suspicious.yar sample.exe
