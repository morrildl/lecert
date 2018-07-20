package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"golang.org/x/crypto/acme"

	"playground/config"
	"playground/log"
)

type configType struct {
	Debug                                               bool
	FQDN                                                string
	AccountJSONPath, AccountEmail, AccountKeyPath       string
	ServerCertPath, ServerKeyPath                       string
	CloudflareEmail, CloudflareSecret, CloudflareZoneID string
}

func (cfg *configType) prepareCFHeaders(req *http.Request) {
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-Auth-Key", cfg.CloudflareSecret)
	req.Header.Add("X-Auth-Email", cfg.CloudflareEmail)
}

func (cfg *configType) cfZoneURL() string {
	return fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", cfg.CloudflareZoneID)
}

var cfg configType

func createChallengeRecord(fqdn, value string) string {
	key := fmt.Sprintf("_acme-challenge.%s", fqdn)
	payload := struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content"`
	}{"TXT", key, value}
	p, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest(http.MethodPost, cfg.cfZoneURL(), bytes.NewBuffer(p))
	if err != nil {
		panic(err)
	}
	cfg.prepareCFHeaders(req)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	if res.StatusCode > 299 {
		panic(fmt.Sprintf("non-success response from server during create: '%s'", res.Status))
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}
	v := struct {
		Result struct {
			ID string `json:"id"`
		} `json:"result"`
	}{}
	if err = json.Unmarshal(body, &v); err != nil {
		panic(err)
	}

	log.Debug("createChallengeRecord", "created TXT", v.Result.ID, key, value)
	return v.Result.ID
}

func cleanupChallengeRecord(id string) {
	url := fmt.Sprintf("%s/%s", cfg.cfZoneURL(), id)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		panic(err)
	}
	cfg.prepareCFHeaders(req)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	if res.StatusCode > 299 {
		e := struct {
			Errors []*struct {
				Message string `json:"message"`
			} `json:"errors"`
		}{}
		b, _ := ioutil.ReadAll(res.Body)
		json.Unmarshal(b, &e)
		panic(fmt.Sprintf("non-success response from server during delete: '%s'", e.Errors[0].Message))
	}

	log.Debug("cleanupChallengeRecord", "deleted TXT", id)
}

func main() {
	config.Load(&cfg)
	if cfg.Debug {
		log.SetLogLevel(log.LEVEL_DEBUG)
	}

	k, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}
	dur, _ := time.ParseDuration("5s")
	root := context.Background()
	client := &acme.Client{Key: k}
	account := &acme.Account{Contact: []string{"mailto:morrildl@playground.global"}}
	ctx, cancel := context.WithTimeout(root, dur)
	if account, err = client.Register(ctx, account, func(tosURL string) bool { return true }); err != nil {
		panic(err)
	}
	cancel()

	ctx, cancel = context.WithTimeout(root, dur)
	authz, err := client.Authorize(ctx, cfg.FQDN)
	if err != nil {
		panic(err)
	}
	cancel()
	for _, a := range authz.Challenges {
		if a.Type == "dns-01" {
			// sign the challenge generated by LE
			v, err := client.DNS01ChallengeRecord(a.Token)
			if err != nil {
				panic(err)
			}

			// cram the response into DNS, and wait briefly to propagate
			id := createChallengeRecord(cfg.FQDN, v)
			defer cleanupChallengeRecord(id)
			dur, _ = time.ParseDuration("10s")
			time.Sleep(dur)

			// tell LE to check DNS
			ctx, cancel = context.WithTimeout(root, dur)
			c, err := client.Accept(ctx, a)
			if err != nil {
				panic(err)
			}
			cancel()
			log.Debug("main", "accepted challenge with status", c.Status)

			// generate some keymatter to turn into a certificate
			server, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					Country:      []string{"US"},
					Province:     []string{"CA"},
					Locality:     []string{"Palo Alto"},
					Organization: []string{"Playground Global"},
					CommonName:   cfg.FQDN,
				},
				DNSNames:  []string{cfg.FQDN},
				PublicKey: server.PublicKey,
			}
			csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, server)
			if err != nil {
				panic(err)
			}

			// ask LE for the certificate
			ctx, cancel = context.WithTimeout(root, dur)
			crt, _, err := client.CreateCert(ctx, csrBytes, 90*24*time.Hour, true)
			if err != nil {
				panic(err)
			}
			cancel()

			// write cert to disk
			for i, b := range crt {
				if err = ioutil.WriteFile(fmt.Sprintf("out%02d.crt", i), b, 0766); err != nil {
					panic(err)
				}
			}

			// we're good after one challenge
			break
		}

		log.Debug("main", "skipping challenge", a.Type)
	}
}
