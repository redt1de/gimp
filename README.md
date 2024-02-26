

# Attempt at some impacket functionality in pure go.
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
Kerb stuff is based on  forks of [https://github.com/jcmturner/gokrb5](https://github.com/jcmturner/gokrb5) 
 - -> [https://github.com/mfdooom/gokrb5](https://github.com/mfdooom/gokrb5) 
 - -> [https://github.com/lorenz/gokrb5](https://github.com/lorenz/gokrb5)

SMB is based on a fork of [https://github.com/hirochachacha/go-smb2](https://github.com/hirochachacha/go-smb2) -> [https://github.com/lorenz/go-smb2](github.com/lorenz/go-smb2)

LDAP is based on a fork of [https://github.com/go-ldap/ldap/v3](https://github.com/go-ldap/ldap/v3) => [https://github.com/synzack/ldap/v3](https://github.com/synzack/ldap/v3)

