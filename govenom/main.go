package main

import (
	"flag"
	"log"

	"github.com/awgh/shellcode/api"

	_ "github.com/awgh/shellcode/modules"
)

func main() {

	var os, arch, bit string
	flag.StringVar(&os, "o", "linux", "Operating System: linux, windows, or freebsd")
	flag.StringVar(&arch, "a", "intel", "Architecture: intel or arm")
	flag.StringVar(&bit, "b", "64", "Bits (of the Architecture): 32 or 64")
	flag.Parse()

	var osFlag api.Os
	switch os {
	case "linux":
		osFlag = api.Linux
	case "win":
		fallthrough
	case "windows":
		osFlag = api.Windows
	case "freebsd":
		osFlag = api.FreeBSD
	case "osx":
		fallthrough
	case "macos":
		fallthrough
	case "darwin":
		osFlag = api.Darwin
	default:
		log.Fatal("Unknown OS")
	}

	var archFlag api.Arch
	switch arch {
	case "x86":
		fallthrough
	case "amd64":
		fallthrough
	case "intel":
		archFlag = api.Intel
	case "arm":
		archFlag = api.Arm
	default:
		log.Fatal("Unknown Architecture")
	}

	var bitsFlag api.Bits
	switch bit {
	case "32":
		bitsFlag = api.Bits32
	case "64":
		bitsFlag = api.Bits64
	default:
		log.Fatal("Unknown Bits")
	}

	api.PrintShellCodes(osFlag, archFlag, bitsFlag)
}
