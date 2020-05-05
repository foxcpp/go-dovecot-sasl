package dovecotsasl

import (
	"bufio"
	"fmt"
	"io"
	"net"
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

func (c *conn) Close() error {
	return c.C.Close()
}
