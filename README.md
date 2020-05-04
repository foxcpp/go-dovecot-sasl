# go-dovecot-sasl

[![go.dev reference](https://img.shields.io/badge/go.dev-reference-007d9c?style=flat-square)](https://pkg.go.dev/github.com/foxcpp/go-dovecot-sasl)

Go library implementing Dovecot authentication protocol 1.1.
The library is based on
[emersion/go-sasl](https://github.com/emersion/go-sasl).

* Specification: https://wiki.dovecot.org/Design/AuthProtocol 

## Examples

### Client

```go
s, err := net.Dial("unix", "/var/lib/dovecot/sasl.sock")
if err != nil {
    // Handle error.
}

cl := dovecotsasl.NewClient(s)
err := cl.Do("SMTP", 
    sasl.NewPlainClient("", "foxcpp", "1234"), 

    dovecotsasl.RemoteIP(net.IPv4(1,2,3,4)),
    dovecotsasl.Secured,
)
if err != nil {
    // Nope!
}

// Authenticated!
```

### Server

```go
l, err := net.Listen("unix", "/var/lib/maddy/sasl.sock")
if err != nil {
    // Handle error.
}

var authenticator sasl.PlainAuthenticator = func(_, user, pass string) error {
    if user == "foxcpp" && pass == "1234" {
        return nil
    }
    return errors.New("nope!")
}

s := NewServer()
s.AddMechanism("PLAIN", dovecotsasl.Mechanism{}, 
    func(*dovecotsasl.AuthReq) sasl.Server {
        return sasl.NewPlainServer(authenticator)
    })

go s.Serve(l)
```

## License

MIT.
