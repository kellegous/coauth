package coauth

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

var allDonePage = `
<!DOCTYPE html>
<html>
<head>
  <title>All Done</title>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <link href='http://fonts.googleapis.com/css?family=Raleway:400,100' rel='stylesheet' type='text/css'>
  <style>
    body {
      background-color: #fff;
      font-family: 'Raleway', sans-serif;
      font-size: 16px;
      color: #999;
    }
    section {
      background-color: #f6f6f6;
      width: 400px;
      margin: 200px auto;
      padding: 100px;
      border-radius: 4px;
      border: 1px solid #999;
      box-shadow: 0 0 10px rgba(0,0,0,0.1);
    }
    h1, h2 {
      margin:0;
      padding:0;
      text-shadow: 1px 1px 0 #fff;
    }
    h1 {
      font-size: 40px;
    }
    h2 {
      font-size: 24px;
    }
  </style>
</head>
<body>
  <section>
    <h1>All Done</h1>
    <h2>You can close this window now.</h2>
  </section>
</body>
</html>
`

func urlFor(addr net.Addr) string {
	a := addr.String()

	ix := strings.LastIndex(a, ":")
	if ix < 0 {
		return a
	}

	return fmt.Sprintf("http://localhost%s/", a[ix:])
}

func serveConn(c net.Conn, cfg *oauth2.Config) (string, error) {
	defer c.Close()

	req, err := http.ReadRequest(bufio.NewReader(c))
	if err != nil {
		return "", err
	}

	var res http.Response
	res.Header = http.Header(map[string][]string{})

	code := req.FormValue("code")
	if code == "" {
		url := cfg.AuthCodeURL("")
		res.StatusCode = http.StatusTemporaryRedirect
		res.Header.Set("Location", url)
		if err := res.Write(c); err != nil {
			return "", err
		}

		if _, err := fmt.Fprintf(c, "%s\n", url); err != nil {
			return "", err
		}
	} else {
		res.StatusCode = http.StatusOK
		res.ContentLength = int64(len(allDonePage))
		res.Header.Set("Content-Type", "text/html;charset=utf-8")
		if err := res.Write(c); err != nil {
			return "", err
		}

		if _, err := fmt.Fprintln(c, allDonePage); err != nil {
			return "", err
		}
	}

	return code, nil
}

func auth(cfg *oauth2.Config, fn func(string) error) (*oauth2.Token, error) {
	ch := make(chan interface{})

	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}
	defer l.Close()

	cfg.RedirectURL = urlFor(l.Addr())
	if err := fn(cfg.RedirectURL); err != nil {
		return nil, err
	}

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				ch <- err
				return
			}

			code, err := serveConn(c, cfg)
			if err != nil {
				ch <- err
				return
			}

			if code == "" {
				continue
			}

			ch <- code
			return
		}
	}()

	v := <-ch
	switch t := v.(type) {
	case error:
		return nil, t
	case string:
		return cfg.Exchange(context.Background(), t)
	}

	panic("unreachable")
}

// Encode an oauth2 token as a string.
func encodeToken(t *oauth2.Token) ([]byte, error) {
	b, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, base64.URLEncoding.EncodedLen(len(b)))
	base64.URLEncoding.Encode(dst, b)
	return dst, nil
}

// Decode an oauth2 token from a string.
func decodeToken(s []byte, t *oauth2.Token) error {
	dst := make([]byte, base64.URLEncoding.DecodedLen(len(s)))

	n, err := base64.URLEncoding.Decode(dst, s)
	if err != nil {
		return err
	}

	return json.Unmarshal(dst[:n], t)
}

func Read(cfg *oauth2.Config, r io.Reader) (*http.Client, error) {
	t := &oauth2.Token{}

	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if err := decodeToken(b, t); err != nil {
		return nil, err
	}

	return cfg.Client(context.Background(), t), nil
}

func ReadFile(cfg *oauth2.Config, filename string) (*http.Client, error) {
	r, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	return Read(cfg, r)
}

func saveFile(t *oauth2.Token, filename string) error {
	b, err := encodeToken(t)
	if err != nil {
		return err
	}

	w, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer w.Close()

	if _, err := w.Write(b); err != nil {
		return err
	}

	_, err = w.Write([]byte{'\n'})
	return err
}

// Perform the full authentication flow.
func Auth(
	cfg *oauth2.Config,
	filename string,
	f func(string) error) (*http.Client, error) {

	if c, err := ReadFile(cfg, filename); err == nil {
		return c, nil
	}

	t, err := auth(cfg, f)
	if err != nil {
		return nil, err
	}

	if err := saveFile(t, filename); err != nil {
		return nil, err
	}

	return cfg.Client(context.Background(), t), nil
}
