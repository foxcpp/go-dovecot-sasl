package dovecotsasl

import (
	"errors"
	"io/ioutil"
	"net"
	"os"
	"testing"

	"github.com/emersion/go-sasl"
)

func testDir(t *testing.T) string {
	t.Helper()
	dir, err := ioutil.TempDir("", "dovecot-sasl-tests-")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func testListener(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func testDial(t *testing.T, l net.Listener) net.Conn {
	t.Helper()
	conn, err := net.Dial(l.Addr().Network(), l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestSaslPlain(t *testing.T) {
	dir := testDir(t)
	defer os.RemoveAll(dir)

	s := NewServer()
	s.AddMechanism("PLAIN", Mechanism{Plaintext: true}, func(req *AuthReq, cb FuncSASLCallback) sasl.Server {
		return sasl.NewPlainServer(func(_, user, pass string) error {
			if user == "foxcpp" && pass == "1234" {
				cb("foxcpp", nil)
				return nil
			}
			return errors.New("nope")
		})
	})
	defer s.Close()

	l := testListener(t)
	go s.Serve(l)

	conn := testDial(t, l)
	cl, err := NewClient(conn)
	if err != nil {
		t.Fatal(err)
	}

	res, err := cl.Do("smtp", sasl.NewPlainClient("", "foxcpp", "1234"), ParamSecured(SecuredTLS))
	if err != nil {
		t.Fatal(err)
	}
	if res.UserID != "foxcpp" {
		t.Errorf("got UserID = %q, want %q", res.UserID, "foxcpp")
	}

	res, err = cl.Do("smtp", sasl.NewPlainClient("", "foxcpp", "5678"), ParamSecured(SecuredTLS))
	if err == nil {
		t.Fatal("Expected an error")
	}

	var authFail AuthFail
	ok := errors.As(err, &authFail)
	if !ok {
		t.Fatal("Error is not an auth fail:", err)
	}
}
