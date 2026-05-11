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
	if len(params) != 0 {
		if _, err := c.W.WriteRune('\t'); err != nil {
			return err
		}
	}
	for i, p := range params {
		if _, err := c.W.WriteString(tabEscape(p)); err != nil {
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

func tabEscape(s string) string {
	var builder strings.Builder
	for _, b := range []byte(s) {
		switch b {
		case '\t', '\n', '\r', escapeChar:
			builder.WriteByte(escapeChar)
		}
		builder.WriteByte(b)
	}
	return builder.String()
}

const escapeChar = '\001'

func tabUnescape(s string) []string {
	var parts []string
	var partBuilder strings.Builder
	var escaped bool
	for _, b := range []byte(s) {
		if escaped {
			partBuilder.WriteByte(byte(b))
			escaped = false
			continue
		}

		if b == escapeChar {
			escaped = true
			continue
		}
		if b == '\t' {
			parts = append(parts, partBuilder.String())
			partBuilder.Reset()
			continue
		}
		partBuilder.WriteByte(byte(b))
	}
	if partBuilder.Len() > 0 {
		parts = append(parts, partBuilder.String())
	}
	return parts
}

func (c *conn) Readln() (string, []string, error) {
	if !c.R.Scan() {
		if err := c.R.Err(); err != nil {
			return "", nil, err
		}
		return "", nil, io.EOF
	}

	parts := tabUnescape(c.R.Text())
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
