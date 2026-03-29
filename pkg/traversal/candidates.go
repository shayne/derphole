package traversal

import (
	"context"

	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

func GatherCandidates(ctx context.Context, dm *tailcfg.DERPMap) ([]string, error) {
	client := &netcheck.Client{
		Logf:   logger.Discard,
		NetMon: netmon.NewStatic(),
	}
	if err := client.Standalone(ctx, ":0"); err != nil {
		return nil, err
	}

	report, err := client.GetReport(ctx, dm, nil)
	if err != nil {
		return nil, err
	}

	v4, v6 := report.GetGlobalAddrs()
	candidates := make([]string, 0, len(v4)+len(v6))
	for _, addr := range v4 {
		candidates = append(candidates, addr.String())
	}
	for _, addr := range v6 {
		candidates = append(candidates, addr.String())
	}
	return candidates, nil
}
