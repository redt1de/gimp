package util

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// target input types:
// domain/username:password@host
// domain\username:password@host
// domain\username:password@host:port

const (
	DOMPART = 1 << iota
	USERPART
	PASSPART
	HOSTPART
	DONE
)

// ParseTargetString parses the target string and returns the domain, username, password and host. password and host are optional. if password contains an @ char then the password needs to be surrounded by quotes.
func ParseTargetString(target string) (domain string, username string, password string, host string) {
	target = strings.Replace(target, "\\", "/", -1)
	target = strings.Replace(target, "\n", "", -1)
	curpart := DOMPART
	curStr := ""
	var passquote bool
	for i := 0; i < len(target); i++ {
		switch curpart {
		case DOMPART:
			if target[i] == '/' {
				domain = curStr
				curStr = ""
				curpart = USERPART
				continue
			}
		case USERPART:
			if target[i] == ':' {
				username = curStr
				curStr = ""
				curpart = PASSPART
				continue
			}
			if target[i] == '@' {
				username = curStr
				curStr = ""
				curpart = HOSTPART
				continue
			}
			if i == len(target)-1 {
				curStr += string(target[i])
				username = curStr
				curStr = ""
				curpart = DONE
				continue
			}
		case PASSPART:
			if target[i] == '\'' || target[i] == '"' {
				if passquote {
					passquote = false
					password = curStr
					curStr = ""
					curpart = HOSTPART
					continue
				}
				passquote = true

				continue
			}

			if target[i] == '@' && !passquote {
				password = curStr
				curStr = ""
				curpart = HOSTPART
				continue

			}
			if i == len(target)-1 {
				curStr += string(target[i])
				password = curStr
				curStr = ""
				curpart = DONE
				continue
			}
		case HOSTPART:
			if i == len(target)-1 {
				curStr += string(target[i])
				host = curStr
				continue
			}

		}
		curStr += string(target[i])
	}

	return domain, username, password, host
}

// // Regular expression to parse target information
// var targetRegex = regexp.MustCompile(`(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)`)

// // Regular expression to parse credentials information
// var credentialRegex = regexp.MustCompile(`(?:(?:([^/:]*)/)?([^:]*)(?::(.*))?)?`)

// // parseTarget helps to parse target information.
// // The expected format is: <DOMAIN>/<USERNAME>:<PASSWORD>@HOSTNAME
// func RParseTargetString(target string) (string, string, string, string) {
// 	target = strings.Replace(target, "\\", "/", -1)
// 	matches := targetRegex.FindStringSubmatch(target)
// 	domain, username, password, remoteName := "", "", "", ""

// 	if len(matches) > 1 {
// 		domain = matches[1]
// 	}
// 	if len(matches) > 2 {
// 		username = matches[2]
// 	}
// 	if len(matches) > 3 {
// 		password = matches[3]
// 	}
// 	if len(matches) > 4 {
// 		remoteName = matches[4]
// 	}

// 	// In case the password contains '@'
// 	if len(remoteName) > 0 && len(password) > 0 {
// 		atIndex := regexp.MustCompile(`@`).Split(remoteName, -1)
// 		if len(atIndex) > 1 {
// 			password += "@" + atIndex[0]
// 			remoteName = atIndex[1]
// 		}
// 	}

// 	return domain, username, password, remoteName
// }

// // parseCredentials helps to parse credentials information.
// // The expected format is: <DOMAIN>/<USERNAME>:<PASSWORD>
// func ParseCredentials(credentials string) (string, string, string) {
// 	matches := credentialRegex.FindStringSubmatch(credentials)
// 	domain, username, password := "", "", ""

// 	if len(matches) > 1 {
// 		domain = matches[1]
// 	}
// 	if len(matches) > 2 {
// 		username = matches[2]
// 	}
// 	if len(matches) > 3 {
// 		password = matches[3]
// 	}

// 	return domain, username, password
// }

// // Parse target strings like "domain/username:password@host", "domain\username:password@host". password and host are optional. returns domain, username, password, host, error
// func ParseTargetString(target string) (domain string, username string, password string, host string, port int, err error) {
// 	var hostpart, userpart string
// 	if strings.Contains(target, "@") {
// 		hostpart = strings.Split(target, "@")[1]
// 		userpart = strings.Split(target, "@")[0]
// 	} else {
// 		userpart = target
// 	}
// 	if strings.Contains(hostpart, ":") {
// 		host = strings.Split(hostpart, ":")[0]
// 		port, _ = strconv.Atoi(strings.Split(hostpart, ":")[1])
// 	}

// 	if strings.Contains(userpart, "/") || strings.Contains(userpart, "\\") {
// 		if strings.Contains(userpart, "/") {
// 			domain = strings.Split(userpart, "/")[0]
// 			userpart = strings.Split(userpart, "/")[1]
// 		} else {
// 			domain = strings.Split(userpart, "\\")[0]
// 			userpart = strings.Split(userpart, "\\")[1]
// 		}

// 	}
// 	if strings.Contains(userpart, ":") {
// 		username = strings.Split(userpart, ":")[0]
// 		password = strings.Split(userpart, ":")[1]
// 	} else {
// 		username = userpart
// 	}

// 	return domain, username, password, host, port, nil
// }

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
