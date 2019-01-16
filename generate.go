package shellcode

import (
	"errors"

	"github.com/Binject/shellcode/api"
)

// Generate - makes a shellcode
func Generate(os api.Os, arch api.Arch, bit api.Bits, name string, params api.Parameters) ([]byte, error) {

	gs := api.LookupShellCode(os, arch, bit)
	for _, g := range gs {
		if g.Name == name {
			return g.Function(params)
		}
	}
	return nil, errors.New("No Matching Shellcode Found")
}
