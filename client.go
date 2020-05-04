package dovecotsasl

import (
	"bufio"
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

// LocalIP formats local server IP for use in Client.Do params.
func LocalIP(ip net.IP) string {
	return "lip=" + ip.String()
}

// LocalIP formats local port for use in Client.Do params.
func LocalPort(i uint16) string {
	return "lport=" + strconv.Itoa(int(i))
}

// LocalIP formats remote IP for use in Client.Do params.
func RemoteIP(ip net.IP) string {
	return "rip=" + ip.String()
}

// LocalIP formats remote port for use in Client.Do params.
func RemotePort(i uint16) string {
	return "rport=" + strconv.Itoa(int(i))
}

// Constants for Client.Do params.
// See https://wiki.dovecot.org/Design/AuthProtocol for description.
const (
	Secured         = "secured"
	CertUsername    = "cert_username"
	ValidClientCert = "valid-client-cert"
	NoPenalty       = "no-penalty"
)

// Do performs SASL authentication using Dovecot SASL server and provided
// sasl.Client implementation.
func (c *Client) Do(service string, cl sasl.Client, extraParams ...string) error {
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
	params = append(params, extraParams...)
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
