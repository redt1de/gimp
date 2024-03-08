package goimpacket_test

import "github.com/redt1de/gimp/goimpacket"

var (
	test_impersonate = "eddard.stark"
	test_spn_cifs    = "CIFS/winterfell.NORTH.SEVENKINGDOMS.LOCAL"
	test_spn_ldap    = "LDAP/winterfell.NORTH.SEVENKINGDOMS.LOCAL"
)
var (
	jsPass = goimpacket.ADAccount{
		Domain:   "NORTH.SEVENKINGDOMS.LOCAL",
		DC:       "winterfell.NORTH.SEVENKINGDOMS.LOCAL",
		Username: "jon.snow",
		Password: "iknownothing",
		Kerberos: false,
		// Hash:       "b8d76e56e9dac90539aff05e3ccb1755",
		// HashBytes:  []byte{0xb8, 0xd7, 0x6e, 0x56, 0xe9, 0xda, 0xc9, 0x05, 0x39, 0xaf, 0xf0, 0x5e, 0x3c, 0xcb, 0x17, 0x55},
		// CCachePath: "/tmp/jstgt.ccache",
		// Host: "winterfell.NORTH.SEVENKINGDOMS.LOCAL",
	}

	jsHash = goimpacket.ADAccount{
		Domain:   "NORTH.SEVENKINGDOMS.LOCAL",
		DC:       "winterfell.NORTH.SEVENKINGDOMS.LOCAL",
		Username: "jon.snow",
		// Password: "iknownothing",
		Kerberos: false,
		Hash:     "b8d76e56e9dac90539aff05e3ccb1755",
		// HashBytes: []byte{0xb8, 0xd7, 0x6e, 0x56, 0xe9, 0xda, 0xc9, 0x05, 0x39, 0xaf, 0xf0, 0x5e, 0x3c, 0xcb, 0x17, 0x55},
		// CCachePath: "/tmp/jstgt.ccache",
		// Host: "winterfell.NORTH.SEVENKINGDOMS.LOCAL",
	}

	jsTGT = goimpacket.ADAccount{
		Domain:   "NORTH.SEVENKINGDOMS.LOCAL",
		DC:       "winterfell.NORTH.SEVENKINGDOMS.LOCAL",
		Username: "jon.snow",
		// Password: "iknownothing",
		Kerberos: true,
		// Hash:       "b8d76e56e9dac90539aff05e3ccb1755",
		// HashBytes:  []byte{0xb8, 0xd7, 0x6e, 0x56, 0xe9, 0xda, 0xc9, 0x05, 0x39, 0xaf, 0xf0, 0x5e, 0x3c, 0xcb, 0x17, 0x55},
		CCachePath: "/tmp/jstgt.ccache",
		// Host:       "winterfell.NORTH.SEVENKINGDOMS.LOCAL",
	}

	jsST = goimpacket.ADAccount{
		Domain:   "NORTH.SEVENKINGDOMS.LOCAL",
		DC:       "winterfell.NORTH.SEVENKINGDOMS.LOCAL",
		Username: "jon.snow",
		// Password: "iknownothing",
		Kerberos: true,
		// Hash:       "b8d76e56e9dac90539aff05e3ccb1755",
		// HashBytes:  []byte{0xb8, 0xd7, 0x6e, 0x56, 0xe9, 0xda, 0xc9, 0x05, 0x39, 0xaf, 0xf0, 0x5e, 0x3c, 0xcb, 0x17, 0x55},
		CCachePath: "/tmp/jsst.ccache",
		// Host:       "winterfell.NORTH.SEVENKINGDOMS.LOCAL",
	}
)
