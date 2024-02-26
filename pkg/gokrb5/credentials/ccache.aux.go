package credentials

import (
	"bytes"
	"encoding/binary"
	"os"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/redt1de/gimp/pkg/gokrb5/types"
)

// CCache is the file credentials cache as define here: https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html
// changed from original to export fields.
type CCache struct {
	Version          uint8
	Header           Header
	DefaultPrincipal Principal
	Credentials      []*Credential
	Path             string
}

type Header struct {
	Length uint16
	Fields []HeaderField
}

type HeaderField struct {
	Tag    uint16
	Length uint16
	Value  []byte
}

// Credential cache entry principal struct.
type Principal struct {
	Realm         string
	PrincipalName types.PrincipalName
}

// Credential holds a Kerberos client's ccache credential information.
type Credential struct {
	Client       Principal
	Server       Principal
	Key          types.EncryptionKey
	AuthTime     time.Time
	StartTime    time.Time
	EndTime      time.Time
	RenewTill    time.Time
	IsSKey       bool
	TicketFlags  asn1.BitString
	Addresses    []types.HostAddress
	AuthData     []types.AuthorizationDataEntry
	Ticket       []byte
	SecondTicket []byte
}

// SaveCCache saves a CCache type to a file.
func (c *CCache) Export(cpath string) error {
	var out bytes.Buffer
	endian := binary.BigEndian
	binary.Write(&out, endian, int8(5))

	// HEADER
	binary.Write(&out, endian, c.Version)
	if c.Version == 4 {
		binary.Write(&out, endian, c.Header.Length)
		for _, f := range c.Header.Fields {
			binary.Write(&out, endian, f.Tag)
			binary.Write(&out, endian, f.Length)
			out.Write(f.Value)
		}
	}
	// // PRINCIPAL
	binary.Write(&out, endian, c.DefaultPrincipal.PrincipalName.NameType)
	binary.Write(&out, endian, int32(len(c.DefaultPrincipal.PrincipalName.NameString)))
	binary.Write(&out, endian, int32(len(c.DefaultPrincipal.Realm)))
	out.Write([]byte(c.DefaultPrincipal.Realm))
	for _, n := range c.DefaultPrincipal.PrincipalName.NameString {
		binary.Write(&out, endian, int32(len(n)))
		// binary.Write(&out, endian, []byte(n))
		out.Write([]byte(n))
	}

	// CREDENTIALS
	for _, cred := range c.Credentials {
		binary.Write(&out, endian, cred.Client.PrincipalName.NameType)
		binary.Write(&out, endian, int32(len(cred.Client.PrincipalName.NameString)))
		binary.Write(&out, endian, int32(len(cred.Client.Realm)))
		out.Write([]byte(cred.Client.Realm))
		for _, n := range cred.Client.PrincipalName.NameString {
			binary.Write(&out, endian, int32(len(n)))
			out.Write([]byte(n))
		}
		binary.Write(&out, endian, cred.Server.PrincipalName.NameType) // DIFF TODO, 01 vs 02
		binary.Write(&out, endian, int32(len(cred.Server.PrincipalName.NameString)))
		binary.Write(&out, endian, int32(len(cred.Server.Realm)))
		out.Write([]byte(cred.Server.Realm))

		for _, n := range cred.Server.PrincipalName.NameString {
			binary.Write(&out, endian, int32(len(n)))
			out.Write([]byte(n))
		}
		binary.Write(&out, endian, int16(cred.Key.KeyType))
		binary.Write(&out, endian, int32(32)) // DIFF TODO, idk where "00 00 00 20" comes from

		out.Write(cred.Key.KeyValue)
		binary.Write(&out, endian, int32(cred.AuthTime.Unix()))
		binary.Write(&out, endian, int32(cred.StartTime.Unix()))
		binary.Write(&out, endian, int32(cred.EndTime.Unix()))
		binary.Write(&out, endian, int32(cred.RenewTill.Unix()))
		if cred.IsSKey {
			binary.Write(&out, endian, int8(1))
		} else {
			binary.Write(&out, endian, int8(0))
		}
		out.Write(cred.TicketFlags.Bytes)

		binary.Write(&out, endian, int32(len(cred.Addresses)))
		for _, a := range cred.Addresses {
			binary.Write(&out, endian, int16(a.AddrType))
			binary.Write(&out, endian, int32(len(a.Address)))
			out.Write(a.Address)
		}

		binary.Write(&out, endian, int32(len(cred.AuthData)))
		for _, ad := range cred.AuthData {
			binary.Write(&out, endian, ad.ADType)
			binary.Write(&out, endian, int32(len(ad.ADData)))
			out.Write(ad.ADData)
		}
		binary.Write(&out, endian, int32(len(cred.Ticket)))
		out.Write(cred.Ticket)
		binary.Write(&out, endian, int32(len(cred.SecondTicket)))
		out.Write(cred.SecondTicket)
	}

	// fmt.Println(hex.Dump(out.Bytes()))
	return os.WriteFile(cpath, out.Bytes(), 0600)
}
