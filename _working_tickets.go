package main

import (
	"log"

	"github.com/redt1de/gimp/pkg/gokrb5"
	"github.com/redt1de/gimpacket/pkg/gokrb5/types"
)

func main() {
	cl := gokrb5.GetKerberosClient("NORTH.SEVENKINGDOMS.LOCAL", "winterfell.NORTH.SEVENKINGDOMS.LOCAL", "jon.snow", "iknownothing", "", false, "aes256-cts-hmac-sha1-96", "", 0)
	err := cl.Login()
	if err != nil {
		log.Fatal(err)
	}
	err = cl.Login()
	if err != nil {
		log.Fatal(err)
	}

	cctgt, err := cl.GetTGTAsCCache()
	if err != nil {
		log.Fatal(err)
	}
	cctgt.Export("/tmp/cctgt")

	ccst, err := cl.GetServiceTicketAsCCache("CIFS/winterfell.NORTH.SEVENKINGDOMS.LOCAL")
	if err != nil {
		log.Fatal(err)
	}
	ccst.Export("/tmp/ccst")

	imper := types.PrincipalName{
		NameType: 1,
		NameString: []string{
			"eddard.stark",
		},
	}
	ccsti, err := cl.GetServiceTicketForUserAsCCache("CIFS/winterfell.NORTH.SEVENKINGDOMS.LOCAL", "NORTH.SEVENKINGDOMS.LOCAL", imper)
	if err != nil {
		log.Fatal(err)
	}
	ccsti.Export("/tmp/ccsti")

}
