package geneve

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	// headerLen is the length of a Header.
	headerLen = 8
)

var (
	// errInvalidVersion indicates that a header's version does not match Version.
	errInvalidVersion = errors.New("invalid version in Header")

	// errInvalidVNI indicates that a VNI contains an invalid value.
	errInvalidVNI = errors.New("invalid VNI in Header")
)

// A Header is a Geneve header, as described in the Geneve internet draft,
// Section 3.4.
type Header struct {
	// Version specifies the version of the Geneve header.
	Version uint8

	// FlagOAM specifies if this Header is an OAM (Operations, Administration,
	// and Management) packet, containing a control message instead of a data
	// payload.
	FlagOAM bool

	// FlagCritical specifies if this Header contains one or more options
	// with the critical bit set.
	FlagCritical bool

	// ProtocolType specifies the type of the protocol data unit appearing
	// after the Geneve header.
	ProtocolType ProtocolType

	// VNI specifies the virtual network identifier for a unique element
	// of a virtual network.
	VNI VNI

	// Options contains zero or more Geneve options.
	Options []*Option
}

// MarshalBinary allocates a byte slice and marshals a Header into binary form.
func (h *Header) MarshalBinary() ([]byte, error) {
	// Must use correct Geneve version
	if h.Version != Version {
		return nil, errInvalidVersion
	}

	// VNI must be valid
	if !h.VNI.Valid() {
		return nil, errInvalidVNI
	}

	// Marshal all Options into binary to be appended to Header bytes
	var obs []byte
	for _, o := range h.Options {
		ob, err := o.MarshalBinary()
		if err != nil {
			return nil, err
		}

		obs = append(obs, ob...)
	}

	b := make([]byte, headerLen)
	b[0] |= (h.Version << 6)
	b[0] |= byte(len(obs) / 4)

	if h.FlagOAM {
		b[1] |= (1 << 7)
	}
	if h.FlagCritical {
		b[1] |= (1 << 6)
	}

	binary.BigEndian.PutUint16(b[2:4], uint16(h.ProtocolType))

	// VNI is 24 bits and must leave last 8 bits of Header reserved
	binary.BigEndian.PutUint32(b[4:8], uint32(h.VNI)<<8)

	b = append(b, obs...)
	return b, nil
}

// UnmarshalBinary unmarshals a byte slice into a Header.
func (h *Header) UnmarshalBinary(b []byte) error {
	_, err := h.unmarshalBinaryOffset(b)
	return err
}

// unmarshalBinaryOffset unmarshals a byte slice into a Header, and returns
// the offset of the payload trailing the Header, for consumption within
// this package.
func (h *Header) unmarshalBinaryOffset(b []byte) (int, error) {
	// Must contain enough data to produce a Header
	if len(b) < headerLen {
		return 0, io.ErrUnexpectedEOF
	}

	h.Version = b[0] >> 6

	// Low 6 bits, multiplied by 4, produce options length
	ol := int(b[0]&0x3f) * 4

	if len(b) < headerLen+ol {
		return 0, io.ErrUnexpectedEOF
	}

	h.FlagOAM = (b[1] >> 7) == 1
	h.FlagCritical = ((b[1] & 0x40) >> 6) == 1

	h.ProtocolType = ProtocolType(binary.BigEndian.Uint16(b[2:4]))

	// VNI is 24 bits
	h.VNI = VNI(binary.BigEndian.Uint32(b[4:8]) >> 8)

	// Check for no options present
	if ol == 0 {
		// Payload offset begins after header
		return headerLen, nil
	}

	i := headerLen
	for i <= ol {
		o := new(Option)
		if err := o.UnmarshalBinary(b[i:]); err != nil {
			return 0, err
		}

		// Each option is offset by length of its header and data
		h.Options = append(h.Options, o)
		i += optionHeaderLen + len(o.Data)
	}

	// Payload offset occurs after header and all options
	return i, nil
}
