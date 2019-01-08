package api

import (
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

// PackAddr - packs a jump address
func PackAddr(addr uint32) (string, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, addr)
	if err != nil {
		return "", err
	}
	return string(buf.Bytes()), nil
}

// PackAddr64 - packs a jump address
func PackAddr64(addr uint64) (string, error) {
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
