// Copyright © 2018 Playground Global, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
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

func createDNS01ChallengeRecord(fqdn, value string) string {
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

func cleanupDNS01ChallengeRecord(id string) {
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

func doWithTimeout(root context.Context, f func(context.Context)) {
	dur, _ := time.ParseDuration("7s")
	ctx, cancel := context.WithTimeout(root, dur)
	f(ctx)
	cancel()
}

func loadAccount() (*acme.Account, *rsa.PrivateKey) {
	// attempt to load & parse the RSA (PCKS#1v1.5) key file for the account
	pkcs, err := ioutil.ReadFile(cfg.AccountKeyPath)
	if err != nil {
		log.Debug("loadAccount", "error loading account key (may simply not exist)", err)
		return nil, nil
	}
	key, err := x509.ParsePKCS1PrivateKey(pkcs)
	if err != nil {
		log.Warn("loadAccount", "error parsing account key", err)
		return nil, nil
	}

	// attempt to load & parse a JSON file representing the account with LE
	jsn, err := ioutil.ReadFile(cfg.AccountJSONPath)
	if err != nil {
		log.Debug("loadAccount", "error loading account data (may simply not exist)", err)
		return nil, nil
	}
	acct := &acme.Account{}
	if err := json.Unmarshal(jsn, acct); err != nil {
		log.Warn("loadAccount", "error parsing account json", err)
		return nil, nil
	}

	return acct, key
}

func initClient(parent context.Context) *acme.Client {
	var err error

	account, key := loadAccount()
	client := &acme.Client{}

	// if we didn't find an account, create one & store it for next time
	if account == nil {
		account = &acme.Account{Contact: []string{cfg.AccountEmail}}

		// TODO: probably should upgrade this to use ECC at some point,
		// but Go currently has no implementation for Curve25519, and the P-256 curve is sketchy.
		// So use overkill RSA for now.
		key, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			panic(err)
		}
		client.Key = key

		pkcs := x509.MarshalPKCS1PrivateKey(key)
		if err = ioutil.WriteFile(cfg.AccountKeyPath, pkcs, 0600); err != nil {
			panic(err)
		}

		doWithTimeout(parent, func(ctx context.Context) {
			if account, err = client.Register(ctx, account, func(tosURL string) bool { return true }); err != nil {
				panic(err)
			}
		})

		jsn, err := json.Marshal(account)
		if err != nil {
			panic(err)
		}
		if err = ioutil.WriteFile(cfg.AccountJSONPath, jsn, 0600); err != nil {
			panic(err)
		}
	}

	client.Key = key

	return client
}

func createCSR() []byte {
	var key *rsa.PrivateKey

	// if we couldn't find the server key, generate one
	pkcs, err := ioutil.ReadFile(cfg.ServerKeyPath)
	if err != nil {
		log.Debug("createCSR", "couldn't locate ServerKeyPath, generating new")
		key, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			panic(err)
		}
		pkcs = x509.MarshalPKCS1PrivateKey(key)

		// wrap in PEM since servers (even some that should know better, nginx I'm looking at you)
		// tend to assume PEM instead of raw DER
		pkcs = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkcs})

		if err = ioutil.WriteFile(cfg.ServerKeyPath, pkcs, 0600); err != nil {
			panic(err)
		}
	} else {
		block, _ := pem.Decode(pkcs)
		if key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			panic(err)
		}
	}

	csr := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cfg.FQDN,
		},
		DNSNames:  []string{cfg.FQDN},
		PublicKey: key.PublicKey,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, key)
	if err != nil {
		panic(err)
	}

	return csrBytes
}

func readyForRenewal() bool {
	b, err := ioutil.ReadFile(cfg.ServerCertPath)
	if err != nil {
		return true
	}

	block, _ := pem.Decode(b)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Warn("readyForRenewal", "current cert exists but doesn't parse", err)
		return true
	}

	// renew after 59 days to avoid trigger letsencrypt 30-day warnings
	return time.Now().After(cert.NotBefore.Add(59 * 24 * time.Hour))
}

func main() {
	config.Load(&cfg)
	if cfg.Debug {
		log.SetLogLevel(log.LEVEL_DEBUG)
	}

	if !readyForRenewal() {
		log.Status("main", "current cert is not due for renewal; exiting")
		return
	}

	defer func() {
		if err := recover(); err != nil {
			log.Error("main", "exiting on panic", err)
		}
	}()

	root := context.Background()
	client := initClient(root)

	csr := createCSR()
	crt := [][]byte{}

	doWithTimeout(root, func(ctx context.Context) {
		order, err := client.AuthorizeOrder(ctx, []acme.AuthzID{acme.AuthzID{Type: "dns", Value: cfg.FQDN}})
		if err != nil {
			panic(err)
		}

		// TODO: technically there can be more than one AuthzURL but for our purposes there should be only one
		auth, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
		if err != nil {
			panic(err)
		}

		for _, c := range auth.Challenges {
			if c.Type != "dns-01" {
				log.Debug("main", "skipping challenge", c.Type)
				continue
			}

			// sign the challenge generated by LE
			v, err := client.DNS01ChallengeRecord(c.Token)
			if err != nil {
				panic(err)
			}

			// cram the response into DNS, and wait briefly to propagate
			id := createDNS01ChallengeRecord(cfg.FQDN, v)
			defer cleanupDNS01ChallengeRecord(id)
			dur, _ := time.ParseDuration("10s")
			time.Sleep(dur)

			// tell LE to check DNS
			doWithTimeout(root, func(ctx context.Context) {
				c, err = client.Accept(ctx, c)
				if err != nil {
					panic(err)
				}
			})

			log.Debug("main", "accepted challenge with status", c.Status)

			time.Sleep(dur)

			// ask LE for the certificate
			doWithTimeout(root, func(ctx context.Context) {
				crt, _, err = client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
				if err != nil {
					panic(err)
				}
			})

			// write cert to disk
			bundle := bytes.Buffer{}
			for _, b := range crt {
				b = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})
				bundle.Write(b)
			}
			b := bundle.Bytes()
			if err = ioutil.WriteFile(cfg.ServerCertPath, b, 0600); err != nil {
				panic(err)
			}

			// we're good after one challenge
			log.Status("main", "certificate renewed")
			return
		}
	})

	if len(crt) < 1 {
		log.Error("main", "could not find supported challenge, no certificate issued")
	}
}
