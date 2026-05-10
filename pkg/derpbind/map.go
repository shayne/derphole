// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derpbind

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"tailscale.com/net/dnsfallback"
	"tailscale.com/tailcfg"
)

const PublicDERPMapURL = "https://controlplane.tailscale.com/derpmap/default"

func FetchMap(ctx context.Context, url string) (*tailcfg.DERPMap, error) {
	if url == PublicDERPMapURL {
		return dnsfallback.GetDERPMap(), nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch derp map: %s", res.Status)
	}

	var dm tailcfg.DERPMap
	if err := json.NewDecoder(res.Body).Decode(&dm); err != nil {
		return nil, err
	}
	return &dm, nil
}
