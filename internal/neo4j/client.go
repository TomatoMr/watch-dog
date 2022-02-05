package neo4j

import (
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"sync"
	"tomato.com/watch-dog/pkg/option"
)

var metux = &sync.RWMutex{}
var driver neo4j.Driver
var session neo4j.Session

func NewDriver(dbUri, username, password string) error {
	var err error
	driver, err = neo4j.NewDriver(dbUri, neo4j.BasicAuth(username, password, ""))
	if err != nil {
		return err
	}
	session = driver.NewSession(neo4j.SessionConfig{})
	return err
}

func CreateNodeRelation(record *option.Record) error {
	metux.Lock()
	defer metux.Unlock()
	createItemFn := func(tx neo4j.Transaction) (interface{}, error) {
		_, err := tx.Run("merge (n1:Node {Ip: $src_ip4}) merge (n2: Node {Ip: $dst_ip4}) merge (n1)-[r:SOCKET {SrcPort:$src_port, DstPort: $dst_port}]->(n2)", map[string]interface{}{
			"src_ip4":  record.SrcIp4,
			"dst_ip4":  record.DstIp4,
			"src_port": record.SrcPort,
			"dst_port": record.DstPort,
		})
		return nil, err
	}
	_, err := session.WriteTransaction(createItemFn)
	return err
}

func Stop() {
	metux.Lock()
	defer metux.Unlock()
	session.Close()
	driver.Close()
}
