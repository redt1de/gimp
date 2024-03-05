package util

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// target input types:
// domain/username:password@host
// domain\username:password@host

// Parse target strings like "domain/username:password@host", "domain\username:password@host". password and host are optional.
func ParseTarget(target string) (string, string, string, string, error) {
	var domain, username, password, host string
	if strings.Contains(target, "@") {
		host = strings.Split(target, "@")[1]
		target = strings.Split(target, "@")[0]
	}
	if strings.Contains(target, "/") || strings.Contains(target, "\\") {
		if strings.Contains(target, "/") {
			domain = strings.Split(target, "/")[0]
			target = strings.Split(target, "/")[1]
		} else {
			domain = strings.Split(target, "\\")[0]
			target = strings.Split(target, "\\")[1]
		}

	}
	if strings.Contains(target, ":") {
		username = strings.Split(target, ":")[0]
		password = strings.Split(target, ":")[1]
	} else {
		username = target
	}

	return domain, username, password, host, nil
}

func ParseLMandNtHash(in string) (lm, nt []byte, err error) {
	if strings.Contains(in, ":") {
		parts := strings.Split(in, ":")
		if len(parts) != 2 {
			return nil, nil, fmt.Errorf("invalid hash format")
		}
		lm, err = hex.DecodeString(parts[0])
		if err != nil {
			return nil, nil, err
		}
		nt, err = hex.DecodeString(parts[1])
		if err != nil {
			return nil, nil, err
		}
	} else {
		nt, err = hex.DecodeString(in)
		if err != nil {
			return nil, nil, err
		}
	}
	return lm, nt, nil
}

func ParseNtHash(in string) []byte {
	if strings.Contains(in, ":") {
		iwant := strings.Split(in, ":")[1]
		in = iwant
	}
	nt, err := hex.DecodeString(in)
	if err != nil {
		return []byte{}
	}
	return nt
}
