package main

import (
	"flag"
	"log"

	"github.com/awgh/shellcode"
)

func main() {

	var os, arch, bit string
	flag.StringVar(&os, "o", "linux", "Operating System: linux, windows, or freebsd")
	flag.StringVar(&arch, "a", "intel", "Architecture: intel or arm")
	flag.StringVar(&bit, "b", "64", "Bits (of the Architecture): 32 or 64")
	flag.Parse()

	var osFlag shellcode.Os
	switch os {
	case "linux":
		osFlag = shellcode.Linux
	case "win":
		fallthrough
	case "windows":
		osFlag = shellcode.Windows
	case "freebsd":
		osFlag = shellcode.FreeBSD
	default:
		log.Fatal("Unknown OS")
	}

	var archFlag shellcode.Arch
	switch arch {
	case "x86":
		fallthrough
	case "amd64":
		fallthrough
	case "intel":
		archFlag = shellcode.Intel
	case "arm":
		archFlag = shellcode.Arm
	default:
		log.Fatal("Unknown Architecture")
	}

	var bitsFlag shellcode.Bits
	switch bit {
	case "32":
		bitsFlag = shellcode.Bits32
	case "64":
		bitsFlag = shellcode.Bits64
	default:
		log.Fatal("Unknown Bits")
	}

	shellcode.PrintShellCodes(osFlag, archFlag, bitsFlag)
}
