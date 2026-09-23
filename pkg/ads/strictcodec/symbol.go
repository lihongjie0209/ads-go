package strictcodec

import (
	"encoding/binary"
	"fmt"
	"unicode/utf8"

	adssymbol "github.com/jarmocluyse/ads-go/pkg/ads/ads-symbol"
)

const symbolEntryHeaderSize = 30

type Symbol struct {
	IndexGroup  uint32
	IndexOffset uint32
	Size        uint32
	DataType    uint32
	Flags       uint32
	Name        string
	Type        string
	Comment     string
}

func DecodeSymbolUploadInfo(data []byte, maximumSymbols, maximumPayload int) (int, int, error) {
	if len(data) != 8 || maximumSymbols < 1 || maximumPayload < 8 {
		return 0, 0, fmt.Errorf("%w: invalid symbol upload information", ErrInvalidFrame)
	}
	count := uint64(binary.LittleEndian.Uint32(data[0:4]))
	size := uint64(binary.LittleEndian.Uint32(data[4:8]))
	if count > uint64(maximumSymbols) || size > uint64(maximumPayload-8) || (count == 0) != (size == 0) || size < count*symbolEntryHeaderSize {
		return 0, 0, fmt.Errorf("%w: inconsistent or unbounded symbol upload information", ErrInvalidFrame)
	}
	return int(count), int(size), nil
}

func DecodeSymbolTable(data []byte, count, maximumSymbols, maximumPayload int) ([]Symbol, error) {
	if count < 0 || count > maximumSymbols || maximumSymbols < 1 || maximumPayload < 1 || len(data) > maximumPayload {
		return nil, fmt.Errorf("%w: invalid symbol table bounds", ErrInvalidFrame)
	}
	result := make([]Symbol, 0, count)
	offset := 0
	for index := 0; index < count; index++ {
		if len(data)-offset < symbolEntryHeaderSize {
			return nil, fmt.Errorf("%w: symbol %d header is truncated", ErrInvalidFrame, index)
		}
		entryLength := uint64(binary.LittleEndian.Uint32(data[offset : offset+4]))
		if entryLength < symbolEntryHeaderSize || entryLength > uint64(len(data)-offset) {
			return nil, fmt.Errorf("%w: symbol %d entry length is invalid", ErrInvalidFrame, index)
		}
		entry := data[offset : offset+int(entryLength)]
		nameLength := int(binary.LittleEndian.Uint16(entry[24:26]))
		typeLength := int(binary.LittleEndian.Uint16(entry[26:28]))
		commentLength := int(binary.LittleEndian.Uint16(entry[28:30]))
		expected := uint64(symbolEntryHeaderSize) + uint64(nameLength) + 1 + uint64(typeLength) + 1 + uint64(commentLength) + 1
		if entryLength != expected {
			return nil, fmt.Errorf("%w: symbol %d redundant length mismatch", ErrInvalidFrame, index)
		}
		cursor := symbolEntryHeaderSize
		for field, length := range []int{nameLength, typeLength, commentLength} {
			end := cursor + length
			if end >= len(entry) || entry[end] != 0 || !utf8.Valid(entry[cursor:end]) {
				return nil, fmt.Errorf("%w: symbol %d string %d is not NUL-terminated UTF-8", ErrInvalidFrame, index, field)
			}
			cursor = end + 1
		}
		parsed, err := adssymbol.ParseSymbol(entry)
		if err != nil {
			return nil, fmt.Errorf("%w: symbol %d: %v", ErrInvalidFrame, index, err)
		}
		if parsed.Name == "" || parsed.Type == "" {
			return nil, fmt.Errorf("%w: symbol %d name and type must be non-empty", ErrInvalidFrame, index)
		}
		result = append(result, Symbol{
			IndexGroup: parsed.IndexGroup, IndexOffset: parsed.IndexOffset, Size: parsed.Size,
			DataType: uint32(parsed.DataType), Flags: uint32(parsed.Flags),
			Name: parsed.Name, Type: parsed.Type, Comment: parsed.Comment,
		})
		offset += int(entryLength)
	}
	if offset != len(data) {
		return nil, fmt.Errorf("%w: symbol table has trailing bytes or wrong cardinality", ErrInvalidFrame)
	}
	return result, nil
}
