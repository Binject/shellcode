package shellcode

import (
	"encoding/hex"
	"log"
	"path/filepath"
	"testing"

	"github.com/Binject/shellcode/api"
)

func Test_Shellcode_1(t *testing.T) {
	repo := NewRepo("shellcodes")
	_, err := CopyFile(filepath.Join("test", "win32messagebox.bin"), filepath.Join("shellcodes", "windows", "x32", "win32messagebox.bin"))
	if err != nil {
		t.Fatal(err)
	}
	shellcode, err := repo.Lookup(api.Windows, api.Intel32, "*.bin")
	log.Println(hex.Dump(shellcode))
	if err != nil {
		t.Fatal(err)
	}
}
