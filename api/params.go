package api

// Parameters - config arguments for shellcode generating modules
type Parameters struct {
	Ip        string
	Port      uint16
	Entry     uint32
	ShellCode []byte
}
