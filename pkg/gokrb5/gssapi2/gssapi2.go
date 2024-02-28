package gssapi2

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/redt1de/gimp/pkg/gokrb5/asn1tools"
	"github.com/redt1de/gimp/pkg/gokrb5/client"
	"github.com/redt1de/gimp/pkg/gokrb5/crypto"
	"github.com/redt1de/gimp/pkg/gokrb5/gssapi"
	"github.com/redt1de/gimp/pkg/gokrb5/iana/chksumtype"
	"github.com/redt1de/gimp/pkg/gokrb5/iana/flags"
	"github.com/redt1de/gimp/pkg/gokrb5/iana/keyusage"
	"github.com/redt1de/gimp/pkg/gokrb5/messages"
	"github.com/redt1de/gimp/pkg/gokrb5/spnego"
	"github.com/redt1de/gimp/pkg/gokrb5/types"
)

type GSSAPI struct {
	Client *client.Client
	User   types.PrincipalName

	sesskey    types.EncryptionKey
	micSubkey  types.EncryptionKey
	sessSubkey types.EncryptionKey
}

// Create new authenticator checksum for kerberos MechToken
func newAuthenticatorChksum(flags []int) []byte {
	a := make([]byte, 24)
	binary.LittleEndian.PutUint32(a[:4], 16)
	for _, i := range flags {
		if i == gssapi.ContextFlagDeleg {
			x := make([]byte, 28-len(a))
			a = append(a, x...)
		}
		f := binary.LittleEndian.Uint32(a[20:24])
		f |= uint32(i)
		binary.LittleEndian.PutUint32(a[20:24], f)
	}
	return a
}

func (k *GSSAPI) InitSecContext(target string, token []byte, isGSSDelegCreds bool) ([]byte, bool, error) {
	if token == nil {
		var tkt messages.Ticket
		var err, authErr error
		var auth types.Authenticator
		ok, s := k.Client.SessionHasSPN(target) // added this check so we can pull ST from a ccache file
		if ok {
			tkt, k.sesskey, _ = k.Client.GetCachedTicket(s)
			auth, authErr = types.NewAuthenticator(k.Client.Credentials.Realm(), k.User)
		} else {
			if k.User.NameType == 0 {
				tkt, k.sesskey, err = k.Client.GetServiceTicket(target)
				auth, authErr = types.NewAuthenticator(k.Client.Credentials.Domain(), k.Client.Credentials.CName())
			} else {
				tkt, k.sesskey, err = k.Client.GetServiceTicketForUser(target, k.Client.Credentials.Realm(), k.User)
				auth, authErr = types.NewAuthenticator(k.Client.Credentials.Realm(), k.User)
			}
		}

		if err != nil {
			return nil, false, fmt.Errorf("unable to obtain service ticket: %w", err)
		}
		if authErr != nil {
			return nil, false, fmt.Errorf("error creating authenticator: %w", authErr)
		}

		b, _ := asn1.Marshal(gssapi.OIDKRB5.OID())
		b = append(b, 0x01, 0x00)

		auth.Cksum = types.Checksum{
			CksumType: chksumtype.GSSAPI,
			Checksum:  newAuthenticatorChksum([]int{gssapi.ContextFlagMutual, gssapi.ContextFlagConf}),
		}

		etype, err := crypto.GetEtype(k.sesskey.KeyType)
		if err != nil {
			return nil, false, fmt.Errorf("invalid key type: %w", err)
		}
		sk := make([]byte, etype.GetKeyByteSize())
		if _, err := rand.Read(sk); err != nil {
			return nil, false, fmt.Errorf("unable to get randomness: %w", err)
		}
		auth.SubKey = types.EncryptionKey{
			KeyType:  k.sesskey.KeyType,
			KeyValue: sk,
		}
		k.micSubkey = auth.SubKey

		APReq, err := messages.NewAPReq(tkt, k.sesskey, auth)
		if err != nil {
			return nil, false, err
		}
		types.SetFlag(&APReq.APOptions, flags.APOptionMutualRequired)

		tb, err := APReq.Marshal()
		if err != nil {
			return nil, false, err
		}

		b = append(b, tb...)
		return asn1tools.AddASNAppTag(b, 0), true, nil
	} else {
		var t spnego.KRB5Token
		if err := t.Unmarshal(token); err != nil {
			return nil, false, fmt.Errorf("invalid Kerberos token: %w", err)
		}
		if !t.IsAPRep() {
			return nil, false, fmt.Errorf("bad Kerberos response: %v", t)
		}
		data, err := crypto.DecryptEncPart(t.APRep.EncPart, k.sesskey, keyusage.AP_REP_ENCPART)
		if err != nil {
			return nil, false, fmt.Errorf("error decrypting AP_REP: %w", err)
		}
		var payload messages.EncAPRepPart
		if err := payload.Unmarshal(data); err != nil {
			return nil, false, fmt.Errorf("bad encrypted AP_REP part: %w", err)
		}
		if time.Since(payload.CTime).Abs() > k.Client.Config.LibDefaults.Clockskew {
			return nil, false, fmt.Errorf("AP_REP time out of range: %v <=> %v", time.Now(), payload.CTime)
		}
		k.sessSubkey = payload.Subkey
		return []byte{}, false, nil
	}
}

func (k *GSSAPI) GetMIC(bs []byte) []byte {
	token, err := gssapi.NewInitiatorMICToken(bs, k.micSubkey)
	if err != nil {
		return nil
	}

	b, err := token.Marshal()
	if err != nil {
		return nil
	}
	return b
}

func (k *GSSAPI) SessionKey() []byte {
	return k.sessSubkey.KeyValue
}

func (k *GSSAPI) Unwrap(token []byte) ([]byte, error) {
	var t gssapi.WrapToken
	if err := t.Unmarshal(token, true); err != nil {
		return nil, fmt.Errorf("while unmarshaling wrap token: %w", err)
	}
	if ok, err := t.Verify(k.sessSubkey, keyusage.GSSAPI_ACCEPTOR_SEAL); !ok {
		return nil, fmt.Errorf("checksum verification failed: %w", err)
	}
	return t.Payload, nil
}

func (k *GSSAPI) Wrap(payload []byte) ([]byte, error) {
	var t gssapi.WrapToken
	t.Payload = payload
	t.Flags = (1 << 2)
	if err := t.SetCheckSum(k.sessSubkey, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, fmt.Errorf("while calculating MAC: %w", err)
	}
	t.EC = uint16(len(t.CheckSum))
	return t.Marshal()
}
