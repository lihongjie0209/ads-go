package strictcodec

import (
	"encoding/binary"
	"testing"
)

func TestDecodeSymbolUploadInfoEnforcesBoundsAndConsistency(t *testing.T) {
	t.Parallel()
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:4], 2)
	binary.LittleEndian.PutUint32(data[4:8], 80)
	count, size, err := DecodeSymbolUploadInfo(data, 4, 128)
	if err != nil || count != 2 || size != 80 {
		t.Fatalf("count=%d size=%d error=%v", count, size, err)
	}
	invalid := []struct {
		name    string
		data    []byte
		symbols int
		payload int
	}{
		{"short", data[:7], 4, 128},
		{"count bound", data, 1, 128},
		{"payload bound", data, 4, 80},
		{"invalid limits", data, 0, 128},
		{"zero mismatch", func() []byte {
			value := append([]byte(nil), data...)
			binary.LittleEndian.PutUint32(value[:4], 0)
			return value
		}(), 4, 128},
		{"impossible minimum", func() []byte {
			value := append([]byte(nil), data...)
			binary.LittleEndian.PutUint32(value[4:], 59)
			return value
		}(), 4, 128},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if _, _, decodeErr := DecodeSymbolUploadInfo(test.data, test.symbols, test.payload); decodeErr == nil {
				t.Fatal("invalid upload info succeeded")
			}
		})
	}
}

func TestDecodeSymbolTableIsExactStrictAndOwned(t *testing.T) {
	t.Parallel()
	first := symbolEntry("MAIN.value", "DINT", "counter")
	second := symbolEntry("MAIN.ready", "BOOL", "")
	table := append(append([]byte(nil), first...), second...)
	symbols, err := DecodeSymbolTable(table, 2, 4, 1024)
	if err != nil || len(symbols) != 2 || symbols[0].Name != "MAIN.value" || symbols[0].Type != "DINT" || symbols[0].Comment != "counter" || symbols[1].Name != "MAIN.ready" {
		t.Fatalf("symbols=%#v error=%v", symbols, err)
	}
	table[30] = 'X'
	if symbols[0].Name != "MAIN.value" {
		t.Fatal("decoded strings alias caller data")
	}

	invalid := []struct {
		name  string
		value []byte
		count int
	}{
		{"truncated", first[:29], 1},
		{"entry length small", mutateUint32(first, 0, 29), 1},
		{"entry length large", mutateUint32(first, 0, uint32(len(first)+1)), 1},
		{"redundant length mismatch", mutateUint32(first, 0, uint32(len(first)-1)), 1},
		{"missing name NUL", mutate(first, 30+len("MAIN.value"), 1), 1},
		{"invalid UTF-8", mutate(first, 30, 0xff), 1},
		{"empty name", symbolEntry("", "DINT", ""), 1},
		{"empty type", symbolEntry("x", "", ""), 1},
		{"wrong cardinality", first, 2},
		{"trailing", append(append([]byte(nil), first...), 0), 1},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if _, decodeErr := DecodeSymbolTable(test.value, test.count, 4, 1024); decodeErr == nil {
				t.Fatal("invalid symbol table succeeded")
			}
		})
	}
	if _, err = DecodeSymbolTable(first, 1, 4, len(first)-1); err == nil {
		t.Fatal("oversized table succeeded")
	}
}

func symbolEntry(name, typeName, comment string) []byte {
	length := 30 + len(name) + 1 + len(typeName) + 1 + len(comment) + 1
	result := make([]byte, length)
	binary.LittleEndian.PutUint32(result[0:4], uint32(length))
	binary.LittleEndian.PutUint32(result[4:8], 0x4020)
	binary.LittleEndian.PutUint32(result[8:12], 7)
	binary.LittleEndian.PutUint32(result[12:16], 4)
	binary.LittleEndian.PutUint32(result[16:20], 3)
	binary.LittleEndian.PutUint32(result[20:24], 8)
	binary.LittleEndian.PutUint16(result[24:26], uint16(len(name)))
	binary.LittleEndian.PutUint16(result[26:28], uint16(len(typeName)))
	binary.LittleEndian.PutUint16(result[28:30], uint16(len(comment)))
	offset := 30
	copy(result[offset:], name)
	offset += len(name) + 1
	copy(result[offset:], typeName)
	offset += len(typeName) + 1
	copy(result[offset:], comment)
	return result
}

func mutateUint32(value []byte, offset int, replacement uint32) []byte {
	result := append([]byte(nil), value...)
	binary.LittleEndian.PutUint32(result[offset:offset+4], replacement)
	return result
}
