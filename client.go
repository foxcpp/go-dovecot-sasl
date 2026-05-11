package dovecotsasl

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"

	"github.com/emersion/go-sasl"
)

type Client struct {
	c    conn
	info ConnInfo
	rid  int
}

func NewClient(netConn net.Conn) (*Client, error) {
	c := Client{
		c: conn{
			C: netConn,
			W: bufio.NewWriter(netConn),
			R: bufio.NewScanner(netConn),
		},
	}

	info, err := c.c.handshakeClient()
	if err != nil {
		return nil, err
	}
	c.info = info

	return &c, nil
}

type Parameter string

// ParamLocalIP formats local server IP for use in Client.Do params.
func ParamLocalIP(ip net.IP) Parameter {
	return "lip=" + Parameter(ip.String())
}

// ParamLocalPort formats local port for use in Client.Do params.
func ParamLocalPort(i uint16) Parameter {
	return "lport=" + Parameter(strconv.Itoa(int(i)))
}

// ParamRemoteIP formats remote IP for use in Client.Do params.
func ParamRemoteIP(ip net.IP) Parameter {
	return "rip=" + Parameter(ip.String())
}

// ParamRemotePort formats remote port for use in Client.Do params.
func ParamRemotePort(i uint16) Parameter {
	return "rport=" + Parameter(strconv.Itoa(int(i)))
}

func ParamSecured(meth SecuredMethod) Parameter {
	if meth == SecuredNone {
		return "secured"
	}
	return "secured=" + Parameter(meth)
}

func ParamTransport(value TransportValue) Parameter {
	return "transport=" + Parameter(value)
}

func ParamTLSCipher(value string) Parameter {
	return "tls_cipher=" + Parameter(value)
}

func ParamTLSCipherBits(bits int) Parameter {
	return "tls_cipher_bits=" + Parameter(strconv.Itoa(bits))
}

func ParamTLSPFS(value string) Parameter {
	return "tls_pfs=" + Parameter(value)
}

func ParamTLSProtocol(version uint16) Parameter {
	switch version {
	case tls.VersionTLS10:
		return "tls_version=TLSv1.0"
	case tls.VersionTLS11:
		return "tls_protocol=TLSv1.1"
	case tls.VersionTLS12:
		return "tls_protocol=TLSv1.2"
	case tls.VersionTLS13:
		return "tls_protocol=TLSv1.3"
	default:
		return "tls_protocol=TLS"
	}
}

// Constants for Client.Do params.
// See https://wiki.dovecot.org/Design/AuthProtocol for description.
const (
	ParamValidClientCert Parameter = "valid-client-cert"
	ParamNoPenalty       Parameter = "no-penalty"
)

// Do performs SASL authentication using Dovecot SASL server and provided
// sasl.Client implementation.
func (c *Client) Do(service string, cl sasl.Client, extraParams ...Parameter) error {
	mech, ir, err := cl.Start()
	if err != nil {
		return err
	}
	if _, ok := c.info.Mechs[mech]; !ok {
		return fmt.Errorf("dovecotsasl: unsupported mechanism: %v", mech)
	}

	c.rid++
	rid := strconv.Itoa(c.rid)

	params := make([]string, 0, 8)
	params = append(params, rid, mech, "service="+service)
	for _, p := range extraParams {
		params = append(params, string(p))
	}
	if ir != nil {
		params = append(params, "resp="+base64.StdEncoding.EncodeToString(ir))
	}

	if err := c.c.Writeln("AUTH", params...); err != nil {
		return err
	}

	for {
		cmd, params, err := c.c.Readln()
		if err != nil {
			return err
		}
		if len(params) == 0 {
			return fmt.Errorf("dovecotsasl: missing reply params")
		}
		if params[0] != rid {
			return fmt.Errorf("dovecotsasl: request ID mismatch, sent %s, received %s", rid, params[0])
		}
		switch cmd {
		case "FAIL":
			return parseFail(params)
		case "CONT":
			if len(params) < 2 {
				return fmt.Errorf("dovecotsasl: missing challenge param")
			}
			challenge, err := base64.StdEncoding.DecodeString(params[1])
			if err != nil {
				return fmt.Errorf("dovecotsasl: malformed challenge: %v", err)
			}
			response, err := cl.Next(challenge)
			if err != nil {
				return err
			}
			err = c.c.Writeln("CONT", rid, base64.StdEncoding.EncodeToString(response))
			if err != nil {
				return err
			}
		case "OK":
			return nil
		}
	}
}

func (c *Client) ConnInfo() ConnInfo {
	return c.info
}

func (cl *Client) Close() error {
	return cl.c.Close()
}
