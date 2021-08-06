package client

import (
	"encoding/json"
	"time"
)

func (cl ChainClient) MineBlock(time time.Time) ([]byte, error) {
	var msg json.RawMessage
	if err := cl.conn.Call(&msg, "evm_mine", time.Unix()); err != nil {
		return nil, err
	}
	return msg, nil
}
