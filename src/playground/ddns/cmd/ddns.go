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
	"fmt"
	"net/http"

	"playground/apiclient"
	"playground/config"
	"playground/log"
)

type configType struct {
	Debug                                               bool
	FQDN                                                string
	IPReflectorURL                                      string
	CloudflareEmail, CloudflareSecret, CloudflareZoneID string
}

var cfg configType

func getIPv4() string {
	c := http.Client{}
	res, err := c.Get(cfg.IPReflectorURL)
	if err != nil {
		panic(err)
	}
	var buf bytes.Buffer
	n, err := buf.ReadFrom(res.Body)
	if err != nil {
		panic(err)
	}
	if n < 1 {
		panic(fmt.Errorf("no data from IP reflector"))
	}
	return buf.String()
}

func setIPv4(fqdn, value string) {
	client := apiclient.API{
		URLBase: "https://api.cloudflare.com",
		Headers: map[string][]string{
			"Content-Type": []string{"application/json"},
			"X-Auth-Key":   []string{cfg.CloudflareSecret},
			"X-Auth-Email": []string{cfg.CloudflareEmail},
		},
	}

	payload := struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content,omitempty"`
		TTL     int    `json:"ttl,omitempty"`
		Proxied bool   `json:"proxied,omitempty"`
	}{"A", fqdn, value, 120, false}
	type result struct {
		ID      string `json:"id"`
		Content string `json:"content"`
	}
	resPayload := &struct {
		Success bool      `json:"success"`
		Errors  []string  `json:"errors"`
		Result  []*result `json:"result"`
	}{}

	endpoint := fmt.Sprintf("/client/v4/zones/%s/dns_records", cfg.CloudflareZoneID)

	log.Debug("setIPv4", fmt.Sprintf("using %s", endpoint))
	if code, err := client.Call(endpoint, http.MethodGet, map[string]string{"type": "A", "name": fqdn}, nil, resPayload); err != nil || code > 299 {
		if code > 299 {
			panic(fmt.Errorf("non-success error code %d from server", code))
		}
		panic(err)
	}
	log.Debug("setIPv4", fmt.Sprintf("result count %d", len(resPayload.Result)))
	if len(resPayload.Result) > 1 {
		for _, r := range resPayload.Result[1:] {
			log.Debug("setIPv4", "deleting", r.Content, r.ID)
			if code, err := client.Call(apiclient.URLJoin(endpoint, r.ID), http.MethodDelete, nil, &struct{}{}, nil); err != nil || code > 299 {
				if code > 299 {
					panic(fmt.Errorf("non-success error code %d from server", code))
				}
				panic(err)
			}
			log.Debug("setIPv4", fmt.Sprintf("deleted record %s", r.ID))
		}
	}

	if len(resPayload.Result) > 0 {
		r := resPayload.Result[0]
		if code, err := client.Call(apiclient.URLJoin(endpoint, r.ID), http.MethodPut, nil, payload, nil); err != nil || code > 299 {
			if code > 299 {
				panic(fmt.Errorf("non-success error code %d from server", code))
			}
			panic(err)
		}
		log.Debug("setIPv4", fmt.Sprintf("updated record %s", r.ID))
		return
	}

	if code, err := client.Call(endpoint, http.MethodPost, nil, payload, nil); err != nil || code > 299 {
		if code > 299 {
			panic(fmt.Errorf("non-success error code %d from server", code))
		}
		panic(err)
	}
	log.Debug("setIPv4", fmt.Sprintf("created record"))

	log.Debug("setIPv4", "set A", fqdn, value)
}

func main() {
	config.Load(&cfg)
	if cfg.Debug {
		log.SetLogLevel(log.LEVEL_DEBUG)
	}

	defer func() {
		if err := recover(); err != nil {
			log.Error("ddns", "exiting on panic", err)
		}
	}()

	log.Debug("ddns", "querying current IP")
	ip := getIPv4()
	if ip != "" {
		log.Debug("ddns", fmt.Sprintf("using IP %s", ip))
		setIPv4(cfg.FQDN, ip)
	}

	log.Status("ddns", fmt.Sprintf("%s set to %s", cfg.FQDN, ip))
}
