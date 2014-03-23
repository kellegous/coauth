package coauth

import (
  "bufio"
  "code.google.com/p/goauth2/oauth"
  "encoding/gob"
  "fmt"
  "io"
  "net"
  "net/http"
)

type Config struct {
  ClientId     string
  ClientSecret string
  Scope        string
  AuthUrl      string
  TokenUrl     string
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

type Client struct {
  t *oauth.Transport
}

func (c *Client) RoundTrip(r *http.Request) (*http.Response, error) {
  return c.t.RoundTrip(r)
}

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
    if _, err := fmt.Fprintln(s, "<h1>All Done! You can close this window now.</h1>"); err != nil {
      return "", err
    }
  }

  return code, nil
}

func newServer(c *oauth.Config) (*server, error) {
  ch := make(chan interface{})

  l, err := net.Listen("tcp", "localhost:0")
  if err != nil {
    return nil, err
  }

  c.RedirectURL = fmt.Sprintf("http://%s/", l.Addr().String())

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
