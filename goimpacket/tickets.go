package goimpacket

import (
	"github.com/redt1de/gimp/goimpacket/gokrb5"
	"github.com/redt1de/gimp/goimpacket/gokrb5/types"
)

func GetTGT(ad *ADAccount, outfile string) error {
	cl := gokrb5.GetKerberosClientEx(ad.Domain, ad.DC, ad.Username, ad.Password, ad.Hash, ad.CCachePath, "", 0)
	err := cl.Login()
	if err != nil {
		return err
	}

	err = cl.CCache.Export(outfile)
	if err != nil {
		return err
	}
	return nil
}

func GetST(ad *ADAccount, spn, impersonate, outfile string) error {
	cl := gokrb5.GetKerberosClientEx(ad.Domain, ad.DC, ad.Username, ad.Password, ad.Hash, ad.CCachePath, "", 0)
	err := cl.Login()
	if err != nil {
		return err
	}

	if impersonate == "" {
		ccst, err := cl.GetServiceTicketAsCCache(spn)
		if err != nil {
			return err
		}

		return ccst.Export(outfile)
	}

	imper := types.PrincipalName{
		NameType: 1,
		NameString: []string{
			impersonate,
		},
	}
	ccsti, err := cl.GetServiceTicketForUserAsCCache(spn, ad.Domain, imper)
	if err != nil {
		return err
	}
	return ccsti.Export(outfile)
}
