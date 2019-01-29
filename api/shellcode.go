package api

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"log"
	"net"
)

type Os string
type Arch string
type Bits string

const (

	// Operating System Options

	// Windows flag for Windows OS
	Windows Os = "windows"
	// Linux flag for Linux OS
	Linux Os = "linux"
	// FreeBSD flag for FreeBSD OS
	FreeBSD Os = "freebsd"
	// Darin flag for Darwin / Mac OS
	Darwin Os = "darwin"

	// Architecture Options

	// Intel flag for Intel/AMD architectures
	Intel Arch = "intel"
	// Arm flag for Arm architectures
	Arm Arch = "arm"

	// Bits Options

	// Bits32 flag for 32 bit architectures
	Bits32 Bits = "32"
	// Bits64 flag for 64 bit architectures
	Bits64 Bits = "64"
)

// Generator - type for a shellcode generator
type Generator struct {
	Os       Os
	Arch     Arch
	Bit      Bits
	Name     string
	Function func(Parameters) ([]byte, error)
}

var generators []Generator

// RegisterShellCode - registers a shellcode generating function with the registry
func RegisterShellCode(
	os Os,
	arch Arch,
	bit Bits,
	name string,
	fx func(Parameters) ([]byte, error)) {

	generators = append(generators, Generator{Os: os, Arch: arch, Bit: bit, Name: name, Function: fx})
}

// LookupShellCode - looks up shellcode by OS and architecture
func LookupShellCode(os Os, arch Arch, bit Bits) []Generator {
	var ret []Generator
	for _, g := range generators {
		if g.Os == os && g.Arch == arch && g.Bit == bit {
			ret = append(ret, g)
		}
	}
	return ret
}

// PrintShellCodes - looks up shellcode by OS and architecture and prints the output
func PrintShellCodes(os Os, arch Arch, bit Bits) {
	gens := LookupShellCode(os, arch, bit)
	for _, g := range gens {
		log.Printf("%+v\n", g)
	}
}

// PackUint16 - packs a jump address
func PackUint16(addr uint16) (string, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, addr)
	if err != nil {
		return "", err
	}
	return string(buf.Bytes()), nil
}

// PackUint32 - packs a jump address
func PackUint32(addr uint32) (string, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, addr)
	if err != nil {
		return "", err
	}
	return string(buf.Bytes()), nil
}

// PackUint64 - packs a jump address
func PackUint64(addr uint64) (string, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, addr)
	if err != nil {
		return "", err
	}
	return string(buf.Bytes()), nil
}

// PackPort - packs a port
func PackPort(port uint16) (string, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, port)
	if err != nil {
		return "", err
	}
	return string(buf.Bytes()), nil
}

// PackIP - packs an IP
func PackIP(ip string) string {
	ipaddr := net.ParseIP(ip).To4()
	return string(ipaddr)
}

// ApplyPrefixForkIntel64 - Prepends instructions to fork and have the parent jump to a relative 32-bit address (the entryJump argument)
//							Intel x64 Linux version
//
//							Returns the resulting shellcode
func ApplyPrefixForkIntel64(shellcode []byte, entryJump uint32, byteOrder binary.ByteOrder) []byte {
	/*
		Disassembly:
		0:  b8 02 00 00 00          mov    eax,0x2
		5:  cd 80                   int    0x80
		7:  83 f8 00                cmp    eax,0x0
		a:  0f 85 xx xx xx xx       jne    <entryJump>
	*/
	prefix := bytes.NewBuffer([]byte{0xB8, 0x02, 0x00, 0x00, 0x00, 0xCD, 0x80, 0x83, 0xF8,
		0x00, 0x0F, 0x85})
	w := bufio.NewWriter(prefix)
	binary.Write(w, byteOrder, entryJump)
	binary.Write(w, byteOrder, shellcode)
	w.Flush()
	return prefix.Bytes()
}
