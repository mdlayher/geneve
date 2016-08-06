package geneve

import (
	"bytes"
	"io"
	"reflect"
	"testing"
)

func TestOptionMarshalBinary(t *testing.T) {
	tests := []struct {
		desc string
		o    *Option
		b    []byte
		err  error
	}{
		{
			desc: "data is not divisible by 4",
			o: &Option{
				Data: []byte{0},
			},
			err: errInvalidOptionDataLength,
		},
		{
			desc: "type too large",
			o: &Option{
				Type: maxOptionType + 1,
			},
			err: errInvalidOptionType,
		},
		{
			desc: "length too large",
			o: &Option{
				Data: make([]byte, (maxOptionLength*4)+4),
			},
			err: errInvalidOptionLength,
		},
		{
			desc: "empty OK",
			o:    &Option{},
			b:    []byte{0, 0, 0, 0},
		},
		{
			desc: "option class OK",
			o: &Option{
				OptionClass: 0xffff,
			},
			b: []byte{0xff, 0xff, 0, 0},
		},
		{
			desc: "flag critical set OK",
			o: &Option{
				FlagCritical: true,
			},
			b: []byte{0, 0, 0x80, 0},
		},
		{
			desc: "type OK",
			o: &Option{
				Type: maxOptionType,
			},
			b: []byte{0, 0, 0x7f, 0},
		},
		{
			desc: "length OK",
			o: &Option{
				Data: make([]byte, maxOptionLength*4),
			},
			b: append([]byte{0, 0, 0, 0x1f}, make([]byte, 124)...),
		},
		{
			desc: "OK",
			o: &Option{
				OptionClass:  0x0001,
				FlagCritical: true,
				Type:         0x02,
				Data:         []byte{0, 1, 2, 3},
			},
			b: []byte{
				0x00, 0x01,
				0x82,
				0x01,
				0, 1, 2, 3,
			},
		},
	}

	for i, tt := range tests {
		t.Logf("[%02d] test %q", i, tt.desc)

		b, err := tt.o.MarshalBinary()
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

func TestOptionUnmarshalBinary(t *testing.T) {
	tests := []struct {
		desc string
		b    []byte
		o    *Option
		err  error
	}{
		{
			desc: "input bytes too short for header",
			b:    []byte{1, 2, 3},
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "input bytes length is not divisible by 4",
			b:    []byte{1, 2, 3, 4, 5},
			err:  errInvalidOptionLength,
		},
		{
			desc: "4 byte option data length",
			b:    []byte{0, 0, 0, 0x01, 1, 2, 3, 4},
			o: &Option{
				Data: []byte{1, 2, 3, 4},
			},
		},
		{
			desc: "4 byte option data length (ignoring reserved high bits in length byte)",
			b:    []byte{0, 0, 0, 0xe1, 1, 2, 3, 4},
			o: &Option{
				Data: []byte{1, 2, 3, 4},
			},
		},
		{
			desc: "input bytes length is less than header + data length",
			b:    []byte{0, 0, 0, 0x02, 0, 0, 0, 0},
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "empty OK",
			b:    []byte{0, 0, 0, 0},
			o: &Option{
				Data: make([]byte, 0),
			},
		},
		{
			desc: "option class OK",
			b:    []byte{0xff, 0xff, 0, 0},
			o: &Option{
				OptionClass: 0xffff,
				Data:        make([]byte, 0),
			},
		},
		{
			desc: "flag critical set OK",
			b:    []byte{0, 0, 0x80, 0},
			o: &Option{
				FlagCritical: true,
				Data:         make([]byte, 0),
			},
		},
		{
			desc: "type OK",
			b:    []byte{0, 0, 0x7f, 0},
			o: &Option{
				Type: maxOptionType,
				Data: make([]byte, 0),
			},
		},
		{
			desc: "length OK",
			b:    append([]byte{0, 0, 0, 0x1f}, make([]byte, 124)...),
			o: &Option{
				Data: make([]byte, maxOptionLength*4),
			},
		},
		{
			desc: "OK",
			b: []byte{
				0x00, 0x01,
				0x82,
				0x01,
				0, 1, 2, 3,
			},
			o: &Option{
				OptionClass:  0x0001,
				FlagCritical: true,
				Type:         0x02,
				Data:         []byte{0, 1, 2, 3},
			},
		},
	}

	for i, tt := range tests {
		t.Logf("[%02d] test %q", i, tt.desc)

		o := new(Option)
		err := o.UnmarshalBinary(tt.b)
		if want, got := tt.err, err; want != got {
			t.Fatalf("unexpected error:\n- want: %v\n-  got: %v", want, got)
		}
		if err != nil {
			continue
		}

		if want, got := tt.o, o; !reflect.DeepEqual(want, got) {
			t.Fatalf("unexpected Option:\n- want: %v\n-  got: %v", want, got)
		}
	}
}
