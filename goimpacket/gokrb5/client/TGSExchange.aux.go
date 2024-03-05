package client

import (
	"github.com/redt1de/gimp/goimpacket/gokrb5/iana/nametype"
	"github.com/redt1de/gimp/goimpacket/gokrb5/messages"
	"github.com/redt1de/gimp/goimpacket/gokrb5/types"
)

func (cl *Client) GetMSPrincipalTicket(spn string) (messages.Ticket, types.EncryptionKey, error) {
	var tkt messages.Ticket
	var skey types.EncryptionKey
	if tkt, skey, ok := cl.GetCachedTicket(spn); ok {
		// Already a valid ticket in the cache
		return tkt, skey, nil
	}

	princ := types.NewPrincipalName(nametype.KRB_MS_PRINCIPAL, spn)
	realm := cl.spnRealm(princ)

	// if we don't know the SPN's realm, ask the client realm's KDC
	if realm == "" {
		realm = cl.Credentials.Realm()
	}

	tgt, skey, err := cl.sessionTGT(realm)
	if err != nil {
		return tkt, skey, err
	}
	_, tgsRep, err := cl.TGSREQGenerateAndExchange(princ, realm, tgt, skey, false)
	if err != nil {
		return tkt, skey, err
	}
	return tgsRep.Ticket, tgsRep.DecryptedEncPart.Key, nil
}
