package api

// Parameters - config arguments for shellcode generating modules
type Parameters struct {
	Ip        string
	Port      uint16
	Entry     uint32
	Entry64   uint64
	ShellCode []byte
}
