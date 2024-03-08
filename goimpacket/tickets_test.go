package goimpacket_test

import (
	"testing"

	"github.com/redt1de/dbg"
	"github.com/redt1de/gimp/goimpacket"
	"github.com/stretchr/testify/assert"
)

var testlog = dbg.Get("test")

func init() {
	dbg.SetByName("test", true, dbg.LogAll)
}

func TestGetTGT(t *testing.T) {
	dbg.SetByName("test", true, dbg.LogAll)
	var err error
	a := assert.New(t)

	err = goimpacket.GetTGT(&jsPass, "/tmp/jstgt.ccache")
	if err != nil {
		testlog.Errorln(err)

	}
	a.Nil(err)

	// err = goimpacket.GetTGT(&jsHash, "/tmp/jstgt.ccache")
	// if err != nil {
	// 	testlog.Errorln(err)

	// }
	// assert.Nil(t, err)
}

func TestGetST(t *testing.T) {
	a := assert.New(t)
	dbg.SetByName("test", true, dbg.LogAll)
	var err error

	err = goimpacket.GetST(&jsPass, test_spn_cifs, "", "/tmp/jsst.ccache")
	if err != nil {
		testlog.Errorln(err)

	}
	a.Nil(err)

	err = goimpacket.GetST(&jsHash, test_spn_cifs, "", "/tmp/jsst.ccache")
	if err != nil {
		testlog.Errorln(err)

	}
	a.Nil(err)

	err = goimpacket.GetST(&jsTGT, test_spn_cifs, "", "/tmp/jsst.ccache")
	if err != nil {
		testlog.Errorln(err)

	}
	a.Nil(err)

	err = goimpacket.GetST(&jsPass, test_spn_cifs, test_impersonate, "/tmp/jssti.ccache")
	if err != nil {
		testlog.Errorln(err)

	}
	a.Nil(err)

	err = goimpacket.GetST(&jsHash, test_spn_cifs, test_impersonate, "/tmp/jssti.ccache")
	if err != nil {
		testlog.Errorln(err)

	}
	a.Nil(err)

	err = goimpacket.GetST(&jsTGT, test_spn_cifs, test_impersonate, "/tmp/jssti.ccache")
	if err != nil {
		testlog.Errorln(err)

	}
	a.Nil(err)

}
