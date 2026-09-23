package strictcodec

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func TestRequestResponseEnvelopeIsStrictAndOwned(t *testing.T) {
	t.Parallel()
	request := Request{
		Target:  Address{NetID: [6]byte{1, 2, 3, 4, 1, 1}, Port: 851},
		Source:  Address{NetID: [6]byte{5, 6, 7, 8, 1, 1}, Port: 30000},
		Command: 2, InvokeID: 0x12345678, Data: []byte{1, 2, 3},
	}
	encoded, err := EncodeRequest(request, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != 41 || binary.LittleEndian.Uint32(encoded[2:6]) != 35 || binary.LittleEndian.Uint16(encoded[22:24]) != 2 || binary.LittleEndian.Uint16(encoded[24:26]) != RequestFlag || binary.LittleEndian.Uint32(encoded[34:38]) != request.InvokeID {
		t.Fatalf("encoded=%x", encoded)
	}
	frame := responseFrame(request, []byte{9, 8}, 0)
	response, err := DecodeResponse(frame, request, 1024)
	if err != nil || response.Command != 2 || response.InvokeID != request.InvokeID || string(response.Data) != "\x09\x08" {
		t.Fatalf("response=%#v error=%v", response, err)
	}
	frame[len(frame)-1] = 7
	if string(response.Data) != "\x09\x08" {
		t.Fatal("decoded response aliases caller buffer")
	}

	invalid := [][]byte{
		frame[:37],
		append(append([]byte(nil), frame...), 0),
		mutate(frame, 0, 1),
		mutate(frame, 2, frame[2]+1),
		mutate(frame, 6, frame[6]+1),
		mutate(frame, 22, frame[22]+1),
		mutate(frame, 24, 4),
		mutate(frame, 26, frame[26]+1),
		mutate(frame, 30, 1),
		mutate(frame, 34, frame[34]+1),
	}
	for i, value := range invalid {
		if _, decodeErr := DecodeResponse(value, request, 1024); decodeErr == nil {
			t.Errorf("case %d succeeded", i)
		}
	}
	if _, err = DecodeResponse(invalid[8], request, 1024); !errors.Is(err, ErrAMSError) {
		t.Fatalf("AMS error=%v", err)
	}
	request.InvokeID = 0
	if _, err = EncodeRequest(request, 1024); err == nil {
		t.Fatal("zero invoke ID succeeded")
	}
}

func TestCommandCodecsEnforceBoundsAndExactLengths(t *testing.T) {
	t.Parallel()
	read, err := BuildRead(0x4020, 4, 8, 1024)
	if err != nil || len(read) != 12 || binary.LittleEndian.Uint32(read[8:]) != 8 {
		t.Fatalf("read=%x error=%v", read, err)
	}
	readResponse := make([]byte, 11)
	binary.LittleEndian.PutUint32(readResponse[4:8], 3)
	copy(readResponse[8:], []byte{1, 2, 3})
	value, err := DecodeReadResponse(readResponse, 1024)
	if err != nil || string(value) != "\x01\x02\x03" {
		t.Fatalf("value=%x error=%v", value, err)
	}
	readResponse[8] = 9
	if string(value) != "\x01\x02\x03" {
		t.Fatal("read response aliases caller buffer")
	}
	if _, err = DecodeReadResponse(append(readResponse, 0), 1024); err == nil {
		t.Fatal("trailing read response succeeded")
	}
	if _, err = BuildWrite(1, 2, make([]byte, 5), 4); err == nil {
		t.Fatal("oversized write succeeded")
	}
	write, err := BuildWrite(1, 2, []byte{5, 6}, 1024)
	if err != nil || len(write) != 14 || binary.LittleEndian.Uint32(write[8:12]) != 2 {
		t.Fatalf("write=%x error=%v", write, err)
	}
	readWrite, err := BuildReadWrite(0xf003, 0, 4, []byte("MAIN.x\x00"), 1024)
	if err != nil || len(readWrite) != 23 || binary.LittleEndian.Uint32(readWrite[12:16]) != 7 {
		t.Fatalf("readwrite=%x error=%v", readWrite, err)
	}
	control, err := BuildWriteControl(5, 7, []byte{1}, 1024)
	if err != nil || len(control) != 9 || binary.LittleEndian.Uint32(control[4:8]) != 1 {
		t.Fatalf("control=%x error=%v", control, err)
	}
	if err = DecodeResult([]byte{0, 0, 0, 0, 1}); err == nil {
		t.Fatal("trailing result succeeded")
	}
	badResult := make([]byte, 4)
	binary.LittleEndian.PutUint32(badResult, 0x701)
	if err = DecodeResult(badResult); !errors.Is(err, ErrADSError) {
		t.Fatalf("ADS error=%v", err)
	}
}

func TestDeviceAndNotificationCodecs(t *testing.T) {
	t.Parallel()
	infoData := make([]byte, 24)
	infoData[4], infoData[5] = 3, 1
	binary.LittleEndian.PutUint16(infoData[6:8], 4026)
	copy(infoData[8:], "TwinCAT PLC\x00")
	info, err := DecodeDeviceInfo(infoData)
	if err != nil || info.Name != "TwinCAT PLC" || info.Build != 4026 {
		t.Fatalf("info=%#v error=%v", info, err)
	}
	if _, err = DecodeDeviceInfo(append(infoData, 0)); err == nil {
		t.Fatal("trailing device info succeeded")
	}
	stateData := make([]byte, 8)
	binary.LittleEndian.PutUint16(stateData[4:6], 5)
	binary.LittleEndian.PutUint16(stateData[6:8], 9)
	state, err := DecodeReadState(stateData)
	if err != nil || state.ADS != 5 || state.Device != 9 {
		t.Fatalf("state=%#v error=%v", state, err)
	}
	request, err := BuildAddNotification(0x4020, 4, 2, TransModeServerOnChange, 10000, 20000, 1024)
	if err != nil || len(request) != 24 {
		t.Fatalf("notification request=%x error=%v", request, err)
	}
	stream := make([]byte, 30)
	binary.LittleEndian.PutUint32(stream[:4], uint32(len(stream)-4))
	binary.LittleEndian.PutUint32(stream[4:8], 1)
	binary.LittleEndian.PutUint64(stream[8:16], FiletimeUnixEpoch+12345678)
	binary.LittleEndian.PutUint32(stream[16:20], 1)
	binary.LittleEndian.PutUint32(stream[20:24], 77)
	binary.LittleEndian.PutUint32(stream[24:28], 2)
	copy(stream[28:], []byte{1, 2})
	samples, err := DecodeNotification(stream, 1024, 8)
	if err != nil || len(samples) != 1 || samples[0].Timestamp.UnixNano() != 1234567800 || string(samples[0].Data) != "\x01\x02" {
		t.Fatalf("samples=%#v error=%v", samples, err)
	}
	stream[28] = 9
	if string(samples[0].Data) != "\x01\x02" {
		t.Fatal("notification aliases caller buffer")
	}
	if _, err = DecodeNotification(append(stream, 0), 1024, 8); err == nil {
		t.Fatal("trailing notification succeeded")
	}
	if _, err = DecodeNotification(stream, 1024, 0); err == nil {
		t.Fatal("invalid sample bound succeeded")
	}
	if got := Filetime(FiletimeUnixEpoch); !got.Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("epoch=%s", got)
	}
}

func responseFrame(request Request, data []byte, amsError uint32) []byte {
	length := AMSHeaderSize + len(data)
	result := make([]byte, AMSTCPHeaderSize+length)
	binary.LittleEndian.PutUint32(result[2:6], uint32(length))
	copy(result[6:12], request.Source.NetID[:])
	binary.LittleEndian.PutUint16(result[12:14], request.Source.Port)
	copy(result[14:20], request.Target.NetID[:])
	binary.LittleEndian.PutUint16(result[20:22], request.Target.Port)
	binary.LittleEndian.PutUint16(result[22:24], request.Command)
	binary.LittleEndian.PutUint16(result[24:26], ResponseFlag)
	binary.LittleEndian.PutUint32(result[26:30], uint32(len(data)))
	binary.LittleEndian.PutUint32(result[30:34], amsError)
	binary.LittleEndian.PutUint32(result[34:38], request.InvokeID)
	copy(result[38:], data)
	return result
}

func mutate(value []byte, offset int, replacement byte) []byte {
	result := append([]byte(nil), value...)
	result[offset] = replacement
	return result
}
