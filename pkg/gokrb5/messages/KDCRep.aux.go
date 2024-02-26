package messages

import (
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/redt1de/gimp/pkg/gokrb5/credentials"
	"github.com/redt1de/gimp/pkg/gokrb5/types"
)

func (TGSRep *TGSRep) ToCCache() (*credentials.CCache, error) {
	cc := new(credentials.CCache)
	cc.Version = 4

	// HEADER
	cc.Header.Length = 12
	cc.Header.Fields = []credentials.HeaderField{ // forge this for now
		{
			Tag:    1,
			Length: 8,
			Value:  []byte{255, 255, 255, 255, 0, 0, 0, 0},
		},
	}

	// PRINCIPAL
	cc.DefaultPrincipal = credentials.Principal{
		Realm:         TGSRep.CRealm,
		PrincipalName: TGSRep.CName,
	}
	// spew.Dump(ASRep.KDCRepFields.DecryptedEncPart.Key)
	// spew.Dump(ASRep.Ticket)
	cc.Credentials = make([]*credentials.Credential, 0)
	cred := new(credentials.Credential)
	cred.Client = credentials.Principal{
		Realm:         TGSRep.CRealm,
		PrincipalName: TGSRep.CName,
	}

	cred.Server = credentials.Principal{
		Realm: TGSRep.KDCRepFields.DecryptedEncPart.SRealm,
		PrincipalName: types.PrincipalName{
			NameType:   2,
			NameString: TGSRep.Ticket.SName.NameString,
		},
	}
	cred.AuthTime = TGSRep.KDCRepFields.DecryptedEncPart.AuthTime
	cred.StartTime = TGSRep.KDCRepFields.DecryptedEncPart.StartTime
	cred.EndTime = TGSRep.KDCRepFields.DecryptedEncPart.EndTime
	cred.RenewTill = TGSRep.KDCRepFields.DecryptedEncPart.RenewTill
	cred.Key = TGSRep.KDCRepFields.DecryptedEncPart.Key
	cred.Ticket, _ = TGSRep.Ticket.Marshal()
	//(0x50e10000) forwardable, proxiable, renewable, initial, pre_authent, enc_pa_rep
	// TODO need to fetch flags from options/existing ticket.
	tgtops := asn1.BitString{Bytes: []byte{0x50, 0xe1, 0x00, 0x00}}
	cred.TicketFlags = asn1.BitString(tgtops)
	// cred.TicketFlags = TGSRep.Ticket.DecryptedEncPart.Flags // TODO: verify this is the right place to pull flags from.
	cc.Credentials = append(cc.Credentials, cred)
	return cc, nil
}

func (ASRep *ASRep) ToCCache() (*credentials.CCache, error) {
	cc := new(credentials.CCache)
	cc.Version = 4

	// HEADER
	cc.Header.Length = 12
	cc.Header.Fields = []credentials.HeaderField{ // forge this for now
		{
			Tag:    1,
			Length: 8,
			Value:  []byte{255, 255, 255, 255, 0, 0, 0, 0},
		},
	}

	// PRINCIPAL
	cc.DefaultPrincipal = credentials.Principal{
		Realm:         ASRep.CRealm,
		PrincipalName: ASRep.CName,
	}
	// spew.Dump(ASRep.KDCRepFields.DecryptedEncPart.Key)
	// spew.Dump(ASRep.Ticket)
	cc.Credentials = make([]*credentials.Credential, 0)
	cred := new(credentials.Credential)
	cred.Client = credentials.Principal{
		Realm:         ASRep.CRealm,
		PrincipalName: ASRep.CName,
	}
	cred.Server = credentials.Principal{
		Realm: ASRep.KDCRepFields.DecryptedEncPart.SRealm,
		PrincipalName: types.PrincipalName{
			NameType:   2,
			NameString: ASRep.Ticket.SName.NameString,
		},
	}
	cred.AuthTime = ASRep.KDCRepFields.DecryptedEncPart.AuthTime
	cred.StartTime = ASRep.KDCRepFields.DecryptedEncPart.StartTime
	cred.EndTime = ASRep.KDCRepFields.DecryptedEncPart.EndTime
	cred.RenewTill = ASRep.KDCRepFields.DecryptedEncPart.RenewTill
	cred.Key = ASRep.KDCRepFields.DecryptedEncPart.Key
	cred.Ticket, _ = ASRep.Ticket.Marshal()
	//(0x50e10000) forwardable, proxiable, renewable, initial, pre_authent, enc_pa_rep
	// TODO need to fetch flags from options/existing ticket.
	tgtops := asn1.BitString{Bytes: []byte{0x50, 0xe1, 0x00, 0x00}}
	cred.TicketFlags = asn1.BitString(tgtops)
	// cred.TicketFlags = ASRep.Ticket.DecryptedEncPart.Flags // TODO: verify this is the right place to pull flags from.
	cc.Credentials = append(cc.Credentials, cred)
	// spew.Dump(ASRep.KDCRepFields.DecryptedEncPart.Flags)

	return cc, nil
}
