package geneve

import (
	"bytes"
	"io"
	"reflect"
	"testing"
)

func TestHeaderMarshalBinary(t *testing.T) {
	tests := []struct {
		desc string
		h    *Header
		b    []byte
		err  error
	}{
		{
			desc: "invalid version",
			h: &Header{
				Version: Version + 1,
			},
			err: errInvalidVersion,
		},
		{
			desc: "invalid VNI",
			h: &Header{
				VNI: MaxVNI + 1,
			},
			err: errInvalidVNI,
		},
		{
			desc: "flag OAM OK",
			h: &Header{
				FlagOAM: true,
			},
			b: []byte{
				0x00,
				0x80,
				0x00, 0x00,
				0x00, 0x00, 0x00,
				0x00,
			},
		},
		{
			desc: "flag critical OK",
			h: &Header{
				FlagCritical: true,
			},
			b: []byte{
				0x00,
				0x40,
				0x00, 0x00,
				0x00, 0x00, 0x00,
				0x00,
			},
		},
		{
			desc: "both flags OK",
			h: &Header{
				FlagOAM:      true,
				FlagCritical: true,
			},
			b: []byte{
				0x00,
				0xc0,
				0x00, 0x00,
				0x00, 0x00, 0x00,
				0x00,
			},
		},
		{
			desc: "protocol type OK",
			h: &Header{
				ProtocolType: 0x0001,
			},
			b: []byte{
				0x00,
				0x00,
				0x00, 0x01,
				0x00, 0x00, 0x00,
				0x00,
			},
		},
		{
			desc: "VNI OK",
			h: &Header{
				VNI: 0x00030201,
			},
			b: []byte{
				0x00,
				0x00,
				0x00, 0x00,
				0x03, 0x02, 0x01,
				0x00,
			},
		},
		{
			desc: "one Option OK",
			h: &Header{
				Options: []*Option{{
					OptionClass:  0x0001,
					FlagCritical: true,
					Type:         0x02,
					Data:         []byte{0, 1, 2, 3},
				}},
			},
			b: []byte{
				// Header
				0x02,
				0x00,
				0x00, 0x00,
				0x00, 0x00, 0x00,
				0x00,
				// Option
				0x00, 0x01,
				0x82,
				0x01,
				0, 1, 2, 3,
			},
		},
		{
			desc: "two Options OK",
			h: &Header{
				Options: []*Option{
					{
						OptionClass:  0x0001,
						FlagCritical: true,
						Type:         0x02,
						Data:         []byte{0, 1, 2, 3},
					},
					{
						OptionClass: 0x0002,
						Type:        0x04,
						Data:        []byte{4, 5, 6, 7, 8, 9, 10, 11},
					},
				},
			},
			b: []byte{
				// Header
				0x05,
				0x00,
				0x00, 0x00,
				0x00, 0x00, 0x00,
				0x00,
				// Option
				0x00, 0x01,
				0x82,
				0x01,
				0, 1, 2, 3,
				// Option
				0x00, 0x02,
				0x04,
				0x02,
				4, 5, 6, 7, 8, 9, 10, 11,
			},
		},
		{
			desc: "all OK",
			h: &Header{
				Version:      Version,
				FlagOAM:      true,
				FlagCritical: true,
				ProtocolType: ProtocolTypeEthernet,
				VNI:          0x00bbeeff,
				Options: []*Option{
					{
						OptionClass:  0x0001,
						FlagCritical: true,
						Type:         0x02,
						Data:         []byte{0, 1, 2, 3},
					},
					{
						OptionClass: 0x0002,
						Type:        0x04,
						Data:        []byte{4, 5, 6, 7, 8, 9, 10, 11},
					},
				},
			},
			b: []byte{
				// Header
				0x05,
				0xc0,
				0x65, 0x58,
				0xbb, 0xee, 0xff,
				0x00,
				// Option
				0x00, 0x01,
				0x82,
				0x01,
				0, 1, 2, 3,
				// Option
				0x00, 0x02,
				0x04,
				0x02,
				4, 5, 6, 7, 8, 9, 10, 11,
			},
		},
	}

	for i, tt := range tests {
		t.Logf("[%02d] test %q", i, tt.desc)

		b, err := tt.h.MarshalBinary()
		if want, got := tt.err, err; want != got {
			t.Fatalf("unexpected error:\n- want: %v\n-  got: %v", want, got)
		}
		if err != nil {
			continue
		}

		if want, got := tt.b, b; !bytes.Equal(want, got) {
			t.Fatalf("unexpected bytes:\n- want: %v\n-  got: %v", want, got)
		}
	}
}

func TestHeaderUnmarshalBinary(t *testing.T) {
	tests := []struct {
		desc string
		h    *Header
		b    []byte
		err  error
	}{
		{
			desc: "input bytes too short for header",
			b:    make([]byte, headerLen-1),
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "input bytes length is less than header + options length",
			b: []byte{
				0x01,
				0x00,
				0x00, 0x00,
				0x00, 0x00, 0x00,
				0x00,
			},
			err: io.ErrUnexpectedEOF,
		},
		{
			desc: "flag OAM OK",
			b: []byte{
				0x00,
				0x80,
				0x00, 0x00,
				0x00, 0x00, 0x00,
				0x00,
			},
			h: &Header{
				FlagOAM: true,
			},
		},
		{
			desc: "flag critical OK",
			b: []byte{
				0x00,
				0x40,
				0x00, 0x00,
				0x00, 0x00, 0x00,
				0x00,
			},
			h: &Header{
				FlagCritical: true,
			},
		},
		{
			desc: "both flags OK",
			b: []byte{
				0x00,
				0xc0,
				0x00, 0x00,
				0x00, 0x00, 0x00,
				0x00,
			},
			h: &Header{
				FlagOAM:      true,
				FlagCritical: true,
			},
		},
		{
			desc: "protocol type OK",
			b: []byte{
				0x00,
				0x00,
				0x00, 0x01,
				0x00, 0x00, 0x00,
				0x00,
			},
			h: &Header{
				ProtocolType: 0x0001,
			},
		},
		{
			desc: "VNI OK",
			b: []byte{
				0x00,
				0x00,
				0x00, 0x00,
				0x03, 0x02, 0x01,
				0x00,
			},
			h: &Header{
				VNI: 0x00030201,
			},
		},
		{
			desc: "one Option OK",
			b: []byte{
				// Header
				0x02,
				0x00,
				0x00, 0x00,
				0x00, 0x00, 0x00,
				0x00,
				// Option
				0x00, 0x01,
				0x82,
				0x01,
				0, 1, 2, 3,
			},
			h: &Header{
				Options: []*Option{{
					OptionClass:  0x0001,
					FlagCritical: true,
					Type:         0x02,
					Data:         []byte{0, 1, 2, 3},
				}},
			},
		},
		{
			desc: "two Options OK",
			b: []byte{
				// Header
				0x05,
				0x00,
				0x00, 0x00,
				0x00, 0x00, 0x00,
				0x00,
				// Option
				0x00, 0x01,
				0x82,
				0x01,
				0, 1, 2, 3,
				// Option
				0x00, 0x02,
				0x04,
				0x02,
				4, 5, 6, 7, 8, 9, 10, 11,
			},
			h: &Header{
				Options: []*Option{
					{
						OptionClass:  0x0001,
						FlagCritical: true,
						Type:         0x02,
						Data:         []byte{0, 1, 2, 3},
					},
					{
						OptionClass: 0x0002,
						Type:        0x04,
						Data:        []byte{4, 5, 6, 7, 8, 9, 10, 11},
					},
				},
			},
		},
		{
			desc: "all OK",
			b: []byte{
				// Header
				0x05,
				0xc0,
				0x65, 0x58,
				0xbb, 0xee, 0xff,
				0x00,
				// Option
				0x00, 0x01,
				0x82,
				0x01,
				0, 1, 2, 3,
				// Option
				0x00, 0x02,
				0x04,
				0x02,
				4, 5, 6, 7, 8, 9, 10, 11,
			},
			h: &Header{
				Version:      Version,
				FlagOAM:      true,
				FlagCritical: true,
				ProtocolType: ProtocolTypeEthernet,
				VNI:          0x00bbeeff,
				Options: []*Option{
					{
						OptionClass:  0x0001,
						FlagCritical: true,
						Type:         0x02,
						Data:         []byte{0, 1, 2, 3},
					},
					{
						OptionClass: 0x0002,
						Type:        0x04,
						Data:        []byte{4, 5, 6, 7, 8, 9, 10, 11},
					},
				},
			},
		},
	}

	for i, tt := range tests {
		t.Logf("[%02d] test %q", i, tt.desc)

		h := new(Header)
		err := h.UnmarshalBinary(tt.b)
		if want, got := tt.err, err; want != got {
			t.Fatalf("unexpected error:\n- want: %v\n-  got: %v", want, got)
		}
		if err != nil {
			continue
		}

		if want, got := tt.h, h; !reflect.DeepEqual(want, got) {
			t.Fatalf("unexpected Header:\n- want: %v\n-  got: %v", want, got)
		}
	}
}

func TestHeader_unmarshalBinaryOffset(t *testing.T) {
	tests := []struct {
		desc string
		b    []byte
		h    *Header
		off  int
	}{
		{
			desc: "no options OK",
			b: []byte{
				// Header
				0x00,
				0x00,
				0x00, 0x00,
				0x03, 0x02, 0x01,
				0x00,
				// Payload
				1, 2, 3, 4,
			},
			h: &Header{
				VNI: 0x00030201,
			},
			off: 8,
		},
		{
			desc: "two options OK",
			b: []byte{
				// Header
				0x05,
				0xc0,
				0x65, 0x58,
				0xbb, 0xee, 0xff,
				0x00,
				// Option
				0x00, 0x01,
				0x82,
				0x01,
				0, 1, 2, 3,
				// Option
				0x00, 0x02,
				0x04,
				0x02,
				4, 5, 6, 7, 8, 9, 10, 11,
				// Payload
				1, 2, 3, 4,
			},
			off: 28,
			h: &Header{
				Version:      Version,
				FlagOAM:      true,
				FlagCritical: true,
				ProtocolType: ProtocolTypeEthernet,
				VNI:          0x00bbeeff,
				Options: []*Option{
					{
						OptionClass:  0x0001,
						FlagCritical: true,
						Type:         0x02,
						Data:         []byte{0, 1, 2, 3},
					},
					{
						OptionClass: 0x0002,
						Type:        0x04,
						Data:        []byte{4, 5, 6, 7, 8, 9, 10, 11},
					},
				},
			},
		},
	}

	for i, tt := range tests {
		t.Logf("[%02d] test %q", i, tt.desc)

		h := new(Header)
		off, err := h.unmarshalBinaryOffset(tt.b)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if want, got := tt.h, h; !reflect.DeepEqual(want, got) {
			t.Fatalf("unexpected Header:\n- want: %v\n-  got: %v", want, got)
		}

		if want, got := tt.off, off; want != got {
			t.Fatalf("unexpected offset:\n- want: %v\n-  got: %v", want, got)
		}
	}
}
