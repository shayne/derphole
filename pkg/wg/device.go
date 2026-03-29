package wg

import "net/netip"

type NodeConfig struct {
	ListenAddr netip.Addr
	PeerAddr   netip.Addr
}

type Node struct {
	Config NodeConfig
}

func NewNode(cfg NodeConfig) *Node {
	return &Node{Config: cfg}
}
