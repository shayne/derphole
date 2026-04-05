package probe

import (
	"context"
	"net"

	"github.com/shayne/derpcat/pkg/traversal"
)

type DirectResult struct {
	Direct bool
}

func PunchDirect(ctx context.Context, local net.PacketConn, remoteAddr string, remote net.PacketConn, localAddr string) (DirectResult, error) {
	result, err := traversal.ProbeDirect(ctx, local, remoteAddr, remote, localAddr)
	if err != nil {
		return DirectResult{}, err
	}
	return DirectResult{Direct: result.Direct}, nil
}
