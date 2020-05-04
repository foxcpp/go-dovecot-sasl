package dovecotsasl

import (
	"fmt"
	"os"
	"strconv"
)

type Mechanism struct {
	Anonymous      bool
	Plaintext      bool
	Dictonary      bool
	Active         bool
	ForwardSecrecy bool
	MutualAuth     bool
	Private        bool
}

func parseMech(params []string) (string, Mechanism, error) {
	mech := Mechanism{}
	if len(params) == 0 {
		return "", mech, fmt.Errorf("dovecotsasl: missing mechanism name")
	}

	for _, p := range params[1:] {
		switch p {
		case "anonymous":
			mech.Anonymous = true
		case "plaintext":
			mech.Plaintext = true
		case "dictonary":
			mech.Dictonary = true
		case "active":
			mech.Active = true
		case "forward-secrecy":
			mech.ForwardSecrecy = true
		case "mutual-auth":
			mech.MutualAuth = true
		case "private":
			mech.Private = true
		}
		// Ignore unknown params as required by spec.
	}

	return params[0], mech, nil
}

func (mech Mechanism) format(name string) []string {
	params := make([]string, 0, 1+7)
	params = append(params, name)
	if mech.Anonymous {
		params = append(params, "anonymous")
	}
	if mech.Plaintext {
		params = append(params, "plaintext")
	}
	if mech.Dictonary {
		params = append(params, "dictonary")
	}
	if mech.Active {
		params = append(params, "active")
	}
	if mech.ForwardSecrecy {
		params = append(params, "forward-secrecy")
	}
	if mech.MutualAuth {
		params = append(params, "mutual-auth")
	}
	if mech.Private {
		params = append(params, "mutual-auth")
	}
	return params
}

type ConnInfo struct {
	CPID, SPID string

	CUID   string
	Cookie string

	Mechs map[string]Mechanism
}

func (c *conn) handshakeClient() (ConnInfo, error) {
	info := ConnInfo{
		CPID:  strconv.Itoa(os.Getpid()),
		Mechs: make(map[string]Mechanism),
	}

	if err := c.Writeln("VERSION", "1", "1"); err != nil {
		return info, err
	}
	if err := c.Writeln("CPID", info.CPID); err != nil {
		return info, err
	}

	version, err := c.ReadlnExpect("VERSION", 2)
	if err != nil {
		return info, err
	}
	if version[0] != "1" {
		return info, fmt.Errorf("dovecotsasl: incompatible server version: %s.%s", version[0], version[1])
	}

	for {
		cmd, params, err := c.Readln()
		if err != nil {
			return info, err
		}
		if cmd == "DONE" {
			break
		}

		switch cmd {
		case "MECH":
			name, mech, err := parseMech(params)
			if err != nil {
				return info, err
			}
			info.Mechs[name] = mech
		case "SPID":
			if len(params) == 0 {
				return info, fmt.Errorf("dovecotsasl: missing parameter in SPID")
			}
			info.SPID = params[0]
		case "CUID":
			if len(params) == 0 {
				return info, fmt.Errorf("dovecotsasl: missing parameter in CUID")
			}
			info.CUID = params[0]
		case "COOKIE":
			if len(params) == 0 {
				return info, fmt.Errorf("dovecotsasl: missing parameter in COOKIE")
			}
			info.Cookie = params[0]
		}
	}

	return info, nil
}
