package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	bpfgo "tomato.com/watch-dog/daemon/bpf/go"
	"tomato.com/watch-dog/internal/neo4j"
	"tomato.com/watch-dog/pkg/logger"
	"tomato.com/watch-dog/pkg/option"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type Ifaces []*net.Interface

var (
	ifaces Ifaces
)

func getInterfaces() {
	for _, iface := range viper.GetStringSlice(option.Ifaces) {
		if i, err := NewIface(iface); err != nil {
			logger.GetLogger().Error("iface is not exist", zap.String("interface_name", iface))
			continue
		} else {
			ifaces = append(ifaces, i)
		}
	}
	if len(ifaces) <= 0 {
		if ifs, err := net.Interfaces(); err != nil {
			logger.GetLogger().Error("cannot get interfaces", zap.Error(err))
			fmt.Println(err)
			os.Exit(1)
		} else {
			if len(ifs) <= 1 {
				logger.GetLogger().Error("not interfaces")
				os.Exit(1)
			}
			ifaces = append(ifaces, &ifs[1])
		}
	}
	// set interface promisc on
	for _, iface := range ifaces {
		if err := exec.Command("ip", "link", "set", "dev", iface.Name, "promisc", "on").Run(); err != nil {
			logger.GetLogger().Error("set interface failed", zap.String("interface_name", iface.Name), zap.Error(err))
			fmt.Println(exec.Command("ip", "link", "set", "dev", iface.Name, "promisc", "on").String())
			fmt.Println("set interface failed", err.Error())
			os.Exit(1)
		} else {
			logger.GetLogger().Info("set interface successful", zap.String("interface", iface.Name))
		}
	}
}

// beforeCollect do something before watch
func beforeCollect() {
	getInterfaces()
	go attachBpf2If()
}

func NewIface(ifaceName string) (*net.Interface, error) {
	return net.InterfaceByName(ifaceName)
}

func attachBpf2If() {
	ch := make(chan option.Msg, 1<<16)
	defer close(ch)
	ctx, cancel := context.WithCancel(context.Background())
	for _, iface := range ifaces {
		go bpfgo.Attach(ctx, iface.Index, ch)
	}
out:
	for msg := range ch {
		switch msg.MsgType {
		case option.Error:
			logger.GetLogger().Error(msg.MsgExtraInfo, zap.String("msg", msg.MsgContent))
			cancel()
			break out
		case option.Warn:
			logger.GetLogger().Warn(msg.MsgExtraInfo, zap.String("msg", msg.MsgContent))
		default:
			record := fmt.Sprintf("%s:%d->%s:%d",
				msg.MsgRecord.SrcIp4,
				msg.MsgRecord.SrcPort,
				msg.MsgRecord.DstIp4,
				msg.MsgRecord.DstPort)
			logger.GetLogger().Info(msg.MsgExtraInfo, zap.String(msg.MsgRecord.DstIp4, record))
			if err := neo4j.CreateNodeRelation(msg.MsgRecord); err != nil {
				logger.GetLogger().Error(msg.MsgRecord.DstIp4, zap.Error(err))

			}
		}
	}
}
