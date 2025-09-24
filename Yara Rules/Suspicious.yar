import "pe"

rule Suspicious
{
    meta:
        author = "Dheeraj"
        date = "2025-09-23"
        description = "Detect PE files that have common win api imports with xor decryts to identify the xor encryted shellocodes"

    strings:
        $nop_sled       = { 90 90 90 90 90 }

        // XOR stub patterns
        $xor_decrypt = { 31 8A 30 90 }
        

        // ASCII fallback: look for function names in the import table or strings
        $string1 = "VirtualAlloc" ascii nocase
        $string2 = "CreateThread" ascii nocase
        $string3 = "WriteProcessMemory" ascii nocase
        $string4 = "CreateRemoteThread" ascii nocase
        $string5 = "CreateToolhelp32Snapshot" ascii nocase
        $string6 = "VirtualProtect" ascii nocase

    condition:
        // 1) imports: check multiple plausible DLL names for each API
        (
            pe.imports("kernel32.dll","VirtualAlloc") or
            pe.imports("kernelbase.dll","VirtualAlloc") or
            pe.imports("api-ms-win-core-memory-l1-1-0.dll","VirtualAlloc") or

            pe.imports("kernel32.dll","CreateThread") or
            pe.imports("kernelbase.dll","CreateThread") or

            pe.imports("kernel32.dll","WriteProcessMemory") or
            pe.imports("kernelbase.dll","WriteProcessMemory") or

            pe.imports("kernel32.dll","CreateRemoteThread") or
            pe.imports("kernelbase.dll","CreateRemoteThread") or

            pe.imports("kernel32.dll","CreateToolhelp32Snapshot") or
            pe.imports("kernelbase.dll","CreateToolhelp32Snapshot") or

            pe.imports("kernel32.dll","VirtualProtect") or
            pe.imports("kernelbase.dll","VirtualProtect")
        )
        // OR 2) fallback: function-name strings present anywhere in file
        or
        (
            any of ($string*)
        )
        // plus: must also contain shellcode/XOR heuristics
        and
        (
            any of ($nop_sled, $xor_decrypt)
        )
}
