package smb2

import (
	"encoding/asn1"

	"github.com/redt1de/gimp/pkg/gokrb5/client"
	"github.com/redt1de/gimp/pkg/gokrb5/gssapi2"
	"github.com/redt1de/gimp/pkg/gokrb5/types"

	"github.com/redt1de/gimp/pkg/go-smb2/internal/spnego"
)

type KerberosInitiator struct {
	SPN    string
	Client *client.Client
	User   types.PrincipalName

	gssimpl *gssapi2.GSSAPI
}

func (k *KerberosInitiator) oid() asn1.ObjectIdentifier {
	return spnego.KerberosOid
}

func (k *KerberosInitiator) initSecContext() ([]byte, error) {
	if k.gssimpl == nil {
		k.gssimpl = &gssapi2.GSSAPI{
			Client: k.Client,
			User:   k.User,
		}
	}
	token, _, err := k.gssimpl.InitSecContext(k.SPN, nil, false)
	return token, err
}

func (k *KerberosInitiator) acceptSecContext(sc []byte) ([]byte, error) {
	token, _, err := k.gssimpl.InitSecContext(k.SPN, sc, false)
	return token, err
}

func (k *KerberosInitiator) sum(bs []byte) []byte {
	return k.gssimpl.GetMIC(bs)
}

func (k *KerberosInitiator) sessionKey() []byte {
	// Only the first 16 bytes are used, if less than that are available
	// zero padding is added.
	sliced := k.gssimpl.SessionKey()[:16]
	for len(sliced) < 16 {
		sliced = append(sliced, 0x00)
	}
	return sliced
}
