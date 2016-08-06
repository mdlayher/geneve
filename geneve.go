// Package geneve implements marshaling and unmarshaling of Generic Network
// Virtualization Encapsulation (Geneve) headers, as described in the
// IETF internet draft: https://tools.ietf.org/html/draft-ietf-nvo3-geneve-02.
package geneve

const (
	// MaxVNI is the maximum possible value for a VNI: the maximum value
	// of a 24-bit integer.
	MaxVNI = (1 << 24) - 1

	// Version is the current version of the Geneve protocol.
	Version = 0
)

// A ProtocolType specifies the type of the protocol data unit appearing
// after a Geneve header.
type ProtocolType uint16

const (
	// ProtocolTypeEthernet indicates that an Ethernet frame is encapsulated
	// by a Geneve header.
	ProtocolTypeEthernet ProtocolType = 0x6558
)

// A VNI is a 24-bit Virtual Network Identifier.  It is used to designate a
// unique element of a virtual network.  Use its Valid method to determine if
// a VNI contains a valid value.
type VNI uint32

// Valid determines if a VNI is a valid, 24-bit integer.
func (v VNI) Valid() bool {
	return v <= MaxVNI
}
