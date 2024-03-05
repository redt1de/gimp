

# Attempt at some impacket functionality in pure go.
This currently just a testing/PoC repo. Eventually I will break out an actual package.

## TODO:
- [ ] SMB + kerberos is hacky, needs testing and cleanup
- [ ] kerberos initiatior for smb may need tweaked for using TGT/ST. initContext tries to fetch an ST but we may already have one.

#### getTGT: 
- [x] auth with user/pass
- [x] auth with user/hash
- [x] auth with kerberos keytab
- [ ] auth with aes key
- [x] saves TGT to a linux CCACHE file

 #### getST: functional, impersonation works but needs more testing and cleanup in gokrb5
- [x] auth with user/pass
- [x] auth with user/hash
- [x] auth with kerberos keytab
- [ ] auth with aes key
- [x] impersonation/S4U2Self/S4U2Proxy
- [ ] force forwardable
- [x] saves ST to a linux CCACHE file

#### References:
Kerb stuff is based on  forks of [https://github.com/jcmturner/gokrb5](https://github.com/jcmturner/gokrb5), the version in this repo has added support for CCACHE files, mainly exporting and the ability to auth with an ST without a TGT. 
 - [https://github.com/mfdooom/gokrb5](https://github.com/mfdooom/gokrb5) (adds Hash support)
 - [https://github.com/lorenz/gokrb5](https://github.com/lorenz/gokrb5) (adds additional gssapi functionality for use with SMB)

SMB is currently based on: [https://github.com/jfjallid/go-smb](https://github.com/jfjallid/go-smb) which seems like a great project to keep an eye on. I implemented a rudiementary kerberos SessionSetup PoC, until it gets full Kerberos support.

Other SMB projects to keep an eye on:
-> [https://github.com/hirochachacha/go-smb2](https://github.com/hirochachacha/go-smb2) 
-> [https://github.com/lorenz/go-smb2](https://github.com/lorenz/go-smb2)
-> [https://github.com/stacktitan/smb](https://github.com/stacktitan/smb)


LDAP is based on a fork of [https://github.com/go-ldap/ldap/v3](https://github.com/go-ldap/ldap/v3) -> [https://github.com/synzack/ldap/v3](https://github.com/synzack/ldap/v3)




