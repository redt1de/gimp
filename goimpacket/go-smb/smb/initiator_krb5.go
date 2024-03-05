package smb

import (
	"encoding/asn1"

	"github.com/redt1de/gimp/goimpacket/gokrb5/client"
	"github.com/redt1de/gimp/goimpacket/gokrb5/gssapi2"
	"github.com/redt1de/gimp/goimpacket/gokrb5/types"
)

type KerberosInitiator struct {
	TargetSPN          string
	Client             *client.Client
	User               types.PrincipalName
	DisableSigning     bool
	EncryptionDisabled bool
	gssimpl            *gssapi2.GSSAPI
}

func (k *KerberosInitiator) oid() asn1.ObjectIdentifier {
	// return gss.MsKerberosOid
	// var MsKerberosOid = asn1.ObjectIdentifier([]int{1, 2, 840, 48018, 1, 2, 2})
	// var KerberosOid = asn1.ObjectIdentifier([]int{1, 2, 840, 113554, 1, 2, 2})
	return asn1.ObjectIdentifier([]int{1, 2, 840, 113554, 1, 2, 2})
}

func (k *KerberosInitiator) initSecContext() ([]byte, error) {

	if k.gssimpl == nil {
		k.gssimpl = &gssapi2.GSSAPI{
			Client: k.Client,
			User:   k.User,
		}
	}
	token, _, err := k.gssimpl.InitSecContext(k.TargetSPN, nil, false)
	return token, err
}

func (k *KerberosInitiator) acceptSecContext(sc []byte) ([]byte, error) {
	token, _, err := k.gssimpl.InitSecContext(k.TargetSPN, sc, false)
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

func (k *KerberosInitiator) isNullSession() bool {
	return false
}

func (k *KerberosInitiator) getUsername() string {
	return k.Client.Credentials.Domain() + "\\" + k.Client.Credentials.UserName()
	// return  k.Client.Credentials.UserName()
}
