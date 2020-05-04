package dovecotsasl

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

type conn struct {
	C net.Conn
	W *bufio.Writer
	R *bufio.Scanner
}

func (c *conn) Writeln(cmd string, params ...string) error {
	if _, err := c.W.WriteString(cmd); err != nil {
		return err
	}
	if _, err := c.W.WriteRune('\t'); err != nil {
		return err
	}
	for i, p := range params {
		if _, err := c.W.WriteString(p); err != nil {
			return err
		}
		if i != len(params)-1 {
			if _, err := c.W.WriteRune('\t'); err != nil {
				return err
			}
		}
	}
	if _, err := c.W.WriteRune('\n'); err != nil {
		return err
	}

	return c.W.Flush()
}

func (c *conn) Readln() (string, []string, error) {
	if !c.R.Scan() {
		if err := c.R.Err(); err != nil {
			return "", nil, err
		}
		return "", nil, io.EOF
	}

	parts := strings.Split(c.R.Text(), "\t")
	return parts[0], parts[1:], nil
}

func (c *conn) ReadlnExpect(expectCmd string, atleastParams int) ([]string, error) {
	cmd, params, err := c.Readln()
	if err != nil {
		return nil, err
	}
	if cmd != expectCmd {
		return nil, fmt.Errorf("dovecotsasl: unexpected command: %v", cmd)
	}
	if len(params) < atleastParams {
		return nil, fmt.Errorf("dovecotsasl: not enough params for %s: %v", cmd, len(params))
	}

	return params, nil
}

func (c *conn) handshakeServer(cuid string, mechs map[string]Mechanism) (ConnInfo, error) {
	info := ConnInfo{
		SPID:  strconv.Itoa(os.Getpid()),
		CUID:  cuid,
		Mechs: mechs,
	}

	if err := c.Writeln("VERSION", "1", "1"); err != nil {
		return info, err
	}
	if err := c.Writeln("SPID", info.SPID); err != nil {
		return info, err
	}
	if err := c.Writeln("CUID", info.CUID); err != nil {
		return info, err
	}

	cookie := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, cookie); err != nil {
		return info, fmt.Errorf("dovecotsasl: failed to generate cookie: %w", err)
	}
	info.Cookie = hex.EncodeToString(cookie)

	if err := c.Writeln("COOKIE", info.Cookie); err != nil {
		return info, err
	}

	for name, mech := range info.Mechs {
		if err := c.Writeln("MECH", mech.format(name)...); err != nil {
			return info, err
		}
	}

	version, err := c.ReadlnExpect("VERSION", 2)
	if err != nil {
		return info, err
	}
	if version[0] != "1" {
		return info, fmt.Errorf("dovecotsasl: incompatible client version: %s.%s", version[0], version[1])
	}

	cpid, err := c.ReadlnExpect("CPID", 1)
	if err != nil {
		return info, err
	}
	info.CPID = cpid[0]

	return info, c.Writeln("DONE")
}

func (c *conn) Close() error {
	return c.C.Close()
}
