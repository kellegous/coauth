package coauth

import (
  "bufio"
  "code.google.com/p/goauth2/oauth"
  "encoding/gob"
  "fmt"
  "io"
  "net"
  "net/http"
  "strings"
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

// Configuration for the oauth consumer
type Config struct {
  // the client identifier
  ClientId string

  // The client secret, though since this is an installed applicaiton, this is
  // not a secret at all.
  ClientSecret string

  // The level of access being requested. Multiple scope values should
  // be separated by a space.
  Scope string

  // The url the user will need to visit in order to grant access.
  AuthUrl string

  // The url used to fetch a proper token.
  TokenUrl string
}

func (c *Config) config() *oauth.Config {
  return &oauth.Config{
    ClientId:     c.ClientId,
    ClientSecret: c.ClientSecret,
    Scope:        c.Scope,
    AuthURL:      c.AuthUrl,
    TokenURL:     c.TokenUrl,
  }
}

// An http.RoundTripper that signs with the underlying OAuth token.
type Client struct {
  t *oauth.Transport
}

// Provided for http.RoundTripper. Dispatches a Request and parses
// the Response.
func (c *Client) RoundTrip(r *http.Request) (*http.Response, error) {
  return c.t.RoundTrip(r)
}

// Serialize the client's token into the writer.
func (c *Client) Write(w io.Writer) error {
  return gob.NewEncoder(w).Encode(c.t.Token)
}

type server struct {
  c chan interface{}
  u string
}

func handleConn(s net.Conn, c *oauth.Config) (string, error) {
  defer s.Close()

  req, err := http.ReadRequest(bufio.NewReader(s))
  if err != nil {
    return "", err
  }

  code := req.FormValue("code")

  var res http.Response
  res.Header = http.Header(map[string][]string{})

  if code == "" {
    res.StatusCode = http.StatusTemporaryRedirect
    res.Header.Set("Location", c.AuthCodeURL(""))
    if err := res.Write(s); err != nil {
      return "", err
    }
    if _, err := fmt.Fprintf(s, "%s\n", c.RedirectURL); err != nil {
      return "", err
    }
  } else {
    res.Header.Set("Content-Type", "text/html;charset=utf-8")
    if err := res.Write(s); err != nil {
      return "", err
    }
    if _, err := fmt.Fprintln(s, allDonePage); err != nil {
      return "", err
    }
  }

  return code, nil
}

func urlFor(addr net.Addr) string {
  a := addr.String()

  ix := strings.LastIndex(a, ":")
  if ix < 0 {
    return a
  }

  return fmt.Sprintf("http://localhost%s/", a[ix:])
}

func newServer(c *oauth.Config) (*server, error) {
  ch := make(chan interface{})

  l, err := net.Listen("tcp", "localhost:0")
  if err != nil {
    return nil, err
  }

  c.RedirectURL = urlFor(l.Addr())

  go func() {
    for {
      s, err := l.Accept()
      if err != nil {
        ch <- err
        return
      }

      code, err := handleConn(s, c)
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

  return &server{
    c: ch,
    u: c.RedirectURL,
  }, nil
}

func (s *server) url() string {
  return s.u
}

func (s *server) waitForCode() (string, error) {
  v := <-s.c
  switch t := v.(type) {
  case error:
    return "", t
  case string:
    return t, nil
  }
  panic("unreachable")
}

// Deserialize a token from the given reader to resurrect a Client.
func ReadClient(r io.Reader, c *Config) (*Client, error) {
  var t oauth.Token

  if err := gob.NewDecoder(r).Decode(&t); err != nil {
    return nil, err
  }

  return &Client{
    t: &oauth.Transport{
      Config: c.config(),
      Token:  &t,
    },
  }, nil
}

// Perform the full authentication flow.
func Authenticate(c *Config, f func(string) error) (*Client, error) {
  cfg := c.config()

  s, err := newServer(cfg)
  if err != nil {
    return nil, err
  }

  if err := f(s.url()); err != nil {
    return nil, err
  }

  code, err := s.waitForCode()
  if err != nil {
    return nil, err
  }

  t := &oauth.Transport{
    Config: cfg,
  }

  if _, err := t.Exchange(code); err != nil {
    return nil, err
  }

  return &Client{t: t}, nil
}
