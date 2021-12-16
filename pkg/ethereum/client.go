package ethereum

import (
	"github.com/ethereum/go-ethereum/rpc"
)

type Client struct {
	conn *rpc.Client
}

func NewClient(endpoint string) (*Client, error) {
	conn, err := rpc.DialHTTP(endpoint)
	if err != nil {
		return nil, err
	}
	return &Client{
		conn: conn,
	}, nil
}
