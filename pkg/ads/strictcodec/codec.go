// Package strictcodec provides bounded, stateless AMS/TCP and ADS wire codecs.
package strictcodec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

const (
	AMSTCPHeaderSize = 6
	AMSHeaderSize    = 32
	RequestFlag      = 0x0004
	ResponseFlag     = 0x0005

	TransModeServerCycle    = 3
	TransModeServerOnChange = 4
	FiletimeUnixEpoch       = uint64(116444736000000000)
)

var (
	ErrInvalidFrame = errors.New("invalid ADS frame")
	ErrAMSError     = errors.New("AMS error")
	ErrADSError     = errors.New("ADS error")
)

type Address struct {
	NetID [6]byte
	Port  uint16
}

type Request struct {
	Target   Address
	Source   Address
	Command  uint16
	InvokeID uint32
	Data     []byte
}

type Response struct {
	Command  uint16
	InvokeID uint32
	Data     []byte
}

type DeviceInfo struct {
	Major uint8
	Minor uint8
	Build uint16
	Name  string
}

type DeviceState struct {
	ADS    uint16
	Device uint16
}

type NotificationSample struct {
	Handle    uint32
	Timestamp time.Time
	Data      []byte
}

func EncodeRequest(request Request, maximumPayload int) ([]byte, error) {
	if err := validateBound(maximumPayload); err != nil {
		return nil, err
	}
	if request.Target.Port == 0 || request.Source.Port == 0 || request.Command < 1 || request.Command > 9 || request.InvokeID == 0 {
		return nil, fmt.Errorf("%w: invalid request routing or command", ErrInvalidFrame)
	}
	if len(request.Data) > maximumPayload || len(request.Data) > math.MaxUint32-AMSHeaderSize {
		return nil, fmt.Errorf("%w: payload exceeds limit", ErrInvalidFrame)
	}
	result := make([]byte, AMSTCPHeaderSize+AMSHeaderSize+len(request.Data))
	binary.LittleEndian.PutUint32(result[2:6], uint32(AMSHeaderSize+len(request.Data)))
	copy(result[6:12], request.Target.NetID[:])
	binary.LittleEndian.PutUint16(result[12:14], request.Target.Port)
	copy(result[14:20], request.Source.NetID[:])
	binary.LittleEndian.PutUint16(result[20:22], request.Source.Port)
	binary.LittleEndian.PutUint16(result[22:24], request.Command)
	binary.LittleEndian.PutUint16(result[24:26], RequestFlag)
	binary.LittleEndian.PutUint32(result[26:30], uint32(len(request.Data)))
	binary.LittleEndian.PutUint32(result[34:38], request.InvokeID)
	copy(result[38:], request.Data)
	return result, nil
}

func DecodeResponse(encoded []byte, request Request, maximumPayload int) (Response, error) {
	if err := validateBound(maximumPayload); err != nil {
		return Response{}, err
	}
	if len(encoded) < AMSTCPHeaderSize+AMSHeaderSize || encoded[0] != 0 || encoded[1] != 0 {
		return Response{}, fmt.Errorf("%w: invalid AMS/TCP header", ErrInvalidFrame)
	}
	packetLength := binary.LittleEndian.Uint32(encoded[2:6])
	if packetLength < AMSHeaderSize || uint64(packetLength) != uint64(len(encoded)-AMSTCPHeaderSize) {
		return Response{}, fmt.Errorf("%w: inconsistent AMS/TCP length", ErrInvalidFrame)
	}
	dataLength := binary.LittleEndian.Uint32(encoded[26:30])
	if dataLength > uint32(maximumPayload) || uint64(dataLength)+AMSHeaderSize != uint64(packetLength) {
		return Response{}, fmt.Errorf("%w: inconsistent ADS payload length", ErrInvalidFrame)
	}
	if string(encoded[6:12]) != string(request.Source.NetID[:]) || binary.LittleEndian.Uint16(encoded[12:14]) != request.Source.Port ||
		string(encoded[14:20]) != string(request.Target.NetID[:]) || binary.LittleEndian.Uint16(encoded[20:22]) != request.Target.Port ||
		binary.LittleEndian.Uint16(encoded[22:24]) != request.Command || binary.LittleEndian.Uint16(encoded[24:26]) != ResponseFlag ||
		binary.LittleEndian.Uint32(encoded[34:38]) != request.InvokeID {
		return Response{}, fmt.Errorf("%w: response correlation mismatch", ErrInvalidFrame)
	}
	if code := binary.LittleEndian.Uint32(encoded[30:34]); code != 0 {
		return Response{}, fmt.Errorf("%w: 0x%08x", ErrAMSError, code)
	}
	data := append([]byte(nil), encoded[38:]...)
	return Response{Command: request.Command, InvokeID: request.InvokeID, Data: data}, nil
}

func BuildRead(indexGroup, indexOffset uint32, length, maximumPayload int) ([]byte, error) {
	if err := validateBound(maximumPayload); err != nil || maximumPayload < 12 || length < 0 || length > maximumPayload-8 {
		return nil, fmt.Errorf("%w: invalid read length", ErrInvalidFrame)
	}
	result := make([]byte, 12)
	binary.LittleEndian.PutUint32(result[0:4], indexGroup)
	binary.LittleEndian.PutUint32(result[4:8], indexOffset)
	binary.LittleEndian.PutUint32(result[8:12], uint32(length))
	return result, nil
}

func DecodeReadResponse(data []byte, maximumPayload int) ([]byte, error) {
	if err := validateBound(maximumPayload); err != nil {
		return nil, err
	}
	if len(data) < 8 {
		return nil, fmt.Errorf("%w: short read response", ErrInvalidFrame)
	}
	if err := decodeResultPrefix(data); err != nil {
		return nil, err
	}
	length := binary.LittleEndian.Uint32(data[4:8])
	if length > uint32(maximumPayload) || uint64(length)+8 != uint64(len(data)) {
		return nil, fmt.Errorf("%w: invalid read response length", ErrInvalidFrame)
	}
	return append([]byte(nil), data[8:]...), nil
}

func BuildWrite(indexGroup, indexOffset uint32, value []byte, maximumPayload int) ([]byte, error) {
	if err := validateBound(maximumPayload); err != nil || maximumPayload < 12 || len(value) > maximumPayload-12 {
		return nil, fmt.Errorf("%w: invalid write length", ErrInvalidFrame)
	}
	result := make([]byte, 12+len(value))
	binary.LittleEndian.PutUint32(result[0:4], indexGroup)
	binary.LittleEndian.PutUint32(result[4:8], indexOffset)
	binary.LittleEndian.PutUint32(result[8:12], uint32(len(value)))
	copy(result[12:], value)
	return result, nil
}

func DecodeResult(data []byte) error {
	if len(data) != 4 {
		return fmt.Errorf("%w: result must be exactly four bytes", ErrInvalidFrame)
	}
	return decodeResultPrefix(data)
}

func BuildReadWrite(indexGroup, indexOffset uint32, readLength int, value []byte, maximumPayload int) ([]byte, error) {
	if err := validLength(readLength, maximumPayload); err != nil {
		return nil, err
	}
	if err := validLength(len(value), maximumPayload); err != nil {
		return nil, err
	}
	if len(value) > maximumPayload-16 {
		return nil, fmt.Errorf("%w: request exceeds payload limit", ErrInvalidFrame)
	}
	result := make([]byte, 16+len(value))
	binary.LittleEndian.PutUint32(result[0:4], indexGroup)
	binary.LittleEndian.PutUint32(result[4:8], indexOffset)
	binary.LittleEndian.PutUint32(result[8:12], uint32(readLength))
	binary.LittleEndian.PutUint32(result[12:16], uint32(len(value)))
	copy(result[16:], value)
	return result, nil
}

func DecodeDeviceInfo(data []byte) (DeviceInfo, error) {
	if len(data) != 24 {
		return DeviceInfo{}, fmt.Errorf("%w: device info must be exactly 24 bytes", ErrInvalidFrame)
	}
	if err := decodeResultPrefix(data); err != nil {
		return DeviceInfo{}, err
	}
	raw := data[8:24]
	end := len(raw)
	if index := strings.IndexByte(string(raw), 0); index >= 0 {
		end = index
	}
	for _, value := range raw[:end] {
		if value < 0x20 || value > 0x7e {
			return DeviceInfo{}, fmt.Errorf("%w: device name is not printable ASCII", ErrInvalidFrame)
		}
	}
	return DeviceInfo{Major: data[4], Minor: data[5], Build: binary.LittleEndian.Uint16(data[6:8]), Name: string(raw[:end])}, nil
}

func DecodeReadState(data []byte) (DeviceState, error) {
	if len(data) != 8 {
		return DeviceState{}, fmt.Errorf("%w: state response must be exactly eight bytes", ErrInvalidFrame)
	}
	if err := decodeResultPrefix(data); err != nil {
		return DeviceState{}, err
	}
	return DeviceState{ADS: binary.LittleEndian.Uint16(data[4:6]), Device: binary.LittleEndian.Uint16(data[6:8])}, nil
}

func BuildWriteControl(adsState, deviceState uint16, data []byte, maximumPayload int) ([]byte, error) {
	if err := validLength(len(data), maximumPayload); err != nil {
		return nil, err
	}
	if len(data) > maximumPayload-8 {
		return nil, fmt.Errorf("%w: request exceeds payload limit", ErrInvalidFrame)
	}
	result := make([]byte, 8+len(data))
	binary.LittleEndian.PutUint16(result[0:2], adsState)
	binary.LittleEndian.PutUint16(result[2:4], deviceState)
	binary.LittleEndian.PutUint32(result[4:8], uint32(len(data)))
	copy(result[8:], data)
	return result, nil
}

func BuildAddNotification(indexGroup, indexOffset uint32, length int, mode, maxDelay, cycle uint32, maximumPayload int) ([]byte, error) {
	if err := validateBound(maximumPayload); err != nil || maximumPayload < 24 || length < 1 || length > maximumPayload ||
		(mode != TransModeServerCycle && mode != TransModeServerOnChange) || cycle == 0 {
		return nil, fmt.Errorf("%w: unsupported notification mode", ErrInvalidFrame)
	}
	result := make([]byte, 24)
	binary.LittleEndian.PutUint32(result[0:4], indexGroup)
	binary.LittleEndian.PutUint32(result[4:8], indexOffset)
	binary.LittleEndian.PutUint32(result[8:12], uint32(length))
	binary.LittleEndian.PutUint32(result[12:16], mode)
	binary.LittleEndian.PutUint32(result[16:20], maxDelay)
	binary.LittleEndian.PutUint32(result[20:24], cycle)
	return result, nil
}

func DecodeAddNotificationResponse(data []byte) (uint32, error) {
	if len(data) != 8 {
		return 0, fmt.Errorf("%w: add-notification response must be exactly eight bytes", ErrInvalidFrame)
	}
	if err := decodeResultPrefix(data); err != nil {
		return 0, err
	}
	handle := binary.LittleEndian.Uint32(data[4:8])
	if handle == 0 {
		return 0, fmt.Errorf("%w: zero notification handle", ErrInvalidFrame)
	}
	return handle, nil
}

func BuildDeleteNotification(handle uint32) ([]byte, error) {
	if handle == 0 {
		return nil, fmt.Errorf("%w: zero notification handle", ErrInvalidFrame)
	}
	result := make([]byte, 4)
	binary.LittleEndian.PutUint32(result, handle)
	return result, nil
}

func DecodeNotification(data []byte, maximumPayload, maximumSamples int) ([]NotificationSample, error) {
	if err := validateBound(maximumPayload); err != nil || maximumSamples <= 0 {
		return nil, fmt.Errorf("%w: invalid notification bounds", ErrInvalidFrame)
	}
	if len(data) < 8 || len(data) > maximumPayload || binary.LittleEndian.Uint32(data[0:4]) != uint32(len(data)-4) {
		return nil, fmt.Errorf("%w: invalid notification stream length", ErrInvalidFrame)
	}
	stampCount := binary.LittleEndian.Uint32(data[4:8])
	offset := 8
	result := make([]NotificationSample, 0)
	for stamp := uint32(0); stamp < stampCount; stamp++ {
		if len(data)-offset < 12 {
			return nil, fmt.Errorf("%w: truncated notification stamp", ErrInvalidFrame)
		}
		timestamp := Filetime(binary.LittleEndian.Uint64(data[offset : offset+8]))
		sampleCount := binary.LittleEndian.Uint32(data[offset+8 : offset+12])
		offset += 12
		if uint64(len(result))+uint64(sampleCount) > uint64(maximumSamples) {
			return nil, fmt.Errorf("%w: notification sample limit exceeded", ErrInvalidFrame)
		}
		for sample := uint32(0); sample < sampleCount; sample++ {
			if len(data)-offset < 8 {
				return nil, fmt.Errorf("%w: truncated notification sample", ErrInvalidFrame)
			}
			handle := binary.LittleEndian.Uint32(data[offset : offset+4])
			length := binary.LittleEndian.Uint32(data[offset+4 : offset+8])
			offset += 8
			if handle == 0 || length > uint32(maximumPayload) || uint64(length) > uint64(len(data)-offset) {
				return nil, fmt.Errorf("%w: invalid notification sample", ErrInvalidFrame)
			}
			end := offset + int(length)
			result = append(result, NotificationSample{Handle: handle, Timestamp: timestamp, Data: append([]byte(nil), data[offset:end]...)})
			offset = end
		}
	}
	if offset != len(data) {
		return nil, fmt.Errorf("%w: trailing notification bytes", ErrInvalidFrame)
	}
	return result, nil
}

func Filetime(ticks uint64) time.Time {
	if ticks < FiletimeUnixEpoch {
		return time.Unix(0, 0).UTC()
	}
	const ticksPerSecond = uint64(10_000_000)
	delta := ticks - FiletimeUnixEpoch
	seconds := delta / ticksPerSecond
	nanos := (delta % ticksPerSecond) * 100
	if seconds > math.MaxInt64 {
		return time.Unix(math.MaxInt64, 999999999).UTC()
	}
	return time.Unix(int64(seconds), int64(nanos)).UTC()
}

func decodeResultPrefix(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("%w: missing ADS result", ErrInvalidFrame)
	}
	if code := binary.LittleEndian.Uint32(data[:4]); code != 0 {
		return fmt.Errorf("%w: 0x%08x", ErrADSError, code)
	}
	return nil
}

func validateBound(maximumPayload int) error {
	if maximumPayload <= 0 || uint64(maximumPayload) > math.MaxUint32 {
		return fmt.Errorf("%w: invalid payload bound", ErrInvalidFrame)
	}
	return nil
}

func validLength(length, maximumPayload int) error {
	if err := validateBound(maximumPayload); err != nil {
		return err
	}
	if length < 0 || length > maximumPayload || uint64(length) > math.MaxUint32 {
		return fmt.Errorf("%w: length exceeds limit", ErrInvalidFrame)
	}
	return nil
}
