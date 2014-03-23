package coauth

import (
  "bufio"
  "bytes"
  "code.google.com/p/goauth2/oauth"
  "encoding/gob"
  "encoding/json"
  "errors"
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

func (c *Config) config(redirectUrl string) *oauth.Config {
  return &oauth.Config{
    ClientId:     c.ClientId,
    ClientSecret: c.ClientSecret,
    Scope:        c.Scope,
    AuthURL:      c.AuthUrl,
    TokenURL:     c.TokenUrl,
    RedirectURL:  redirectUrl,
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
  l net.Listener
}

func newServer() (*server, error) {
  l, err := net.Listen("tcp", "localhost:0")
  if err != nil {
    return nil, err
  }

  return &server{l}, nil
}

func (s *server) url() string {
  return fmt.Sprintf("http://%s/", s.l.Addr().String())
}

func (s *server) waitForCode() (string, error) {
  defer s.l.Close()

  c, err := s.l.Accept()
  if err != nil {
    return "", err
  }
  defer c.Close()

  req, err := http.ReadRequest(bufio.NewReader(c))
  if err != nil {
    return "", err
  }

  code := req.FormValue("code")
  if code == "" {
    return "", errors.New("Auth service did not return a code.")
  }

  var res http.Response
  res.Header = http.Header(map[string][]string{})
  res.Header.Set("Content-Type", "text/html;charset=utf8")

  res.Write(c)
  fmt.Fprintln(c, "<h1>All Done! You can close this window now.</h1>")

  return code, nil
}

func shortenUrl(url string) (string, error) {
  b, err := json.Marshal(map[string]string{
    "kind":    "urlshortener#url",
    "longUrl": url,
  })
  if err != nil {
    return "", err
  }

  res, err := http.Post("https://www.googleapis.com/urlshortener/v1/url",
    "application/json",
    bytes.NewReader(b))
  if err != nil {
    return "", err
  }
  defer res.Body.Close()

  var s struct {
    Id string `json:"id"`
  }

  if err := json.NewDecoder(res.Body).Decode(&s); err != nil {
    return "", err
  }

  return s.Id, nil
}

func ReadClient(r io.Reader, c *Config) (*Client, error) {
  var t oauth.Token

  if err := gob.NewDecoder(r).Decode(&t); err != nil {
    return nil, err
  }

  return &Client{
    t: &oauth.Transport{
      Config: c.config(""),
      Token:  &t,
    },
  }, nil
}

func Authenticate(c *Config, f func(string) error) (*Client, error) {
  s, err := newServer()
  if err != nil {
    return nil, err
  }

  cfg := c.config(s.url())

  u, err := shortenUrl(cfg.AuthCodeURL(""))
  if err != nil {
    return nil, err
  }

  if err := f(u); err != nil {
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
