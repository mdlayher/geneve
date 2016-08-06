package geneve

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	// maxOptionType is the maximum value for the Option's Type field:
	// a 7-bit integer.
	maxOptionType = (1 << 7) - 1

	// maxOptionLength is the maximum value for an Option's length field:
	// a 5-bit integer.
	maxOptionLength = (1 << 5) - 1

	// optionHeaderLen is the length of an Option header.
	optionHeaderLen = 4
)

var (
	// errInvalidOptionDataLength indicates that an option's data length is not a
	// multiple of 4.
	errInvalidOptionDataLength = errors.New("option data length must be multiple of 4")

	// errInvalidOptionType indicates that an option's type is too large.
	errInvalidOptionType = errors.New("invalid option type")

	// errInvalidOptionLength indicates that an option's length is too large.
	errInvalidOptionLength = errors.New("invalid option length")
)

// An Option is a Geneve option, as described in the Geneve internet draft,
// Section 3.5.
type Option struct {
	// OptionClass specifies an IANA-assigned namespace for Type field.
	OptionClass uint16

	// FlagCritical indicates if this Option is a critical option.
	FlagCritical bool

	// Type specifies the format of data contained in this Option.
	Type uint8

	// Data is arbitrary data whose format is specified by OptionClass and Type.
	Data []byte
}

// MarshalBinary allocates a byte slice and marshals an Option into binary form.
func (o *Option) MarshalBinary() ([]byte, error) {
	// Length of data must be divisible by 4
	if len(o.Data)%4 != 0 {
		return nil, errInvalidOptionDataLength
	}

	// Data length is encoded into byte slice by dividing original length by 4
	ld := len(o.Data) / 4

	// Type and data length must not be greater than protocol limits
	if o.Type > maxOptionType {
		return nil, errInvalidOptionType
	}
	if ld > maxOptionLength {
		return nil, errInvalidOptionLength
	}

	b := make([]byte, optionHeaderLen+len(o.Data))

	binary.BigEndian.PutUint16(b[0:2], o.OptionClass)

	if o.FlagCritical {
		b[2] |= (1 << 7)
	}

	b[2] |= o.Type
	b[3] |= byte(ld)

	copy(b[optionHeaderLen:], o.Data)

	return b, nil
}

// UnmarshalBinary unmarshals a byte slice into an Option.
func (o *Option) UnmarshalBinary(b []byte) error {
	// Must contain enough data to produce an Option header
	if len(b) < optionHeaderLen {
		return io.ErrUnexpectedEOF
	}

	// Length of data must be divisible by 4
	if len(b)%4 != 0 {
		return errInvalidOptionLength
	}

	// Low 5 bits, multiplied by 4, produce data length;
	// input byte slice must be at least as long as option header plus
	// specified data length
	ol := int(b[3]&0x1f) * 4
	if len(b) < optionHeaderLen+ol {
		return io.ErrUnexpectedEOF
	}

	o.OptionClass = binary.BigEndian.Uint16(b[0:2])
	o.FlagCritical = (b[2] >> 7) == 1
	o.Type = b[2] & 0x7f

	o.Data = make([]byte, ol)
	copy(o.Data, b[optionHeaderLen:optionHeaderLen+ol])

	return nil
}
