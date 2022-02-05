package bpfgo

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"tomato.com/watch-dog/pkg/option"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate $GOPATH/bin/bpf2go -objfile collect_bpefel.o -target bpfel collect ../c/collect/collect.c

func Attach(ctx context.Context, index int, ch chan<- option.Msg) {
	if err := rlimit.RemoveMemlock(); err != nil {
		ch <- option.NewMsg(option.Error, "set limit failed", err.Error(), nil)
		return
	}

	objs := collectObjects{}
	if err := loadCollectObjects(&objs, nil); err != nil {
		fmt.Println(err.Error())
		ch <- option.NewMsg(option.Error, "load ebpf program failed", err.Error(), nil)
		return
	}
	defer objs.Close()

	sock, err := openRawSock(index)
	if err != nil {
		ch <- option.NewMsg(option.Error, "bind socket failed", err.Error(), nil)
		return
	}
	defer syscall.Close(sock)

	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, option.SO_ATTACH_BPF, objs.collectPrograms.Collect.FD()); err != nil {
		ch <- option.NewMsg(option.Error, "attach program failed", err.Error(), nil)
		return
	}

	var rd *ringbuf.Reader

	rd, err = ringbuf.NewReader(objs.Records)
	if err != nil {
		ch <- option.NewMsg(option.Error, "init ringbuf failed", err.Error(), nil)
		return
	}
	defer rd.Close()

	for {
		select {
		case <-ctx.Done():
			ch <- option.NewMsg(option.Error, "", "cancel", nil)
		default:
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					ch <- option.NewMsg(option.Error, "ringbuf closed", err.Error(), nil)
					return
				}
				ch <- option.NewMsg(option.Warn, "ringbuf read failed", err.Error(), nil)
				continue
			}

			var flowRecord option.RawRecord
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &flowRecord); err != nil {
				ch <- option.NewMsg(option.Warn, "analyse record failed", err.Error(), nil)
				continue
			}
			ch <- option.NewMsg(option.Normal, "", "ok", flowRecord.Convert())
			time.Sleep(time.Second)
		}
	}
}

func openRawSock(index int) (int, error) {
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return 0, err
	}
	sll := syscall.SockaddrLinklayer{
		Ifindex:  index,
		Protocol: htons(syscall.ETH_P_ALL),
	}
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}
	return sock, nil
}

// htons converts the unsigned short integer hostshort from host byte order to network byte order.
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
