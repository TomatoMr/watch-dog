package option

import "tomato.com/watch-dog/pkg/util"

type MsgType int

const (
	Error  MsgType = -2
	Warn   MsgType = -1
	Normal MsgType = 0
)

type RawRecord struct {
	SrcIp4  uint32
	DstIp4  uint32
	SrcPort uint16
	DstPort uint16
}

type Record struct {
	SrcIp4  string
	DstIp4  string
	SrcPort int
	DstPort int
}

type Msg struct {
	MsgType      MsgType
	MsgExtraInfo string
	MsgContent   string
	MsgRecord    *Record
}

func NewMsg(msgType MsgType, extraInfo, content string, record *Record) Msg {
	return Msg{
		MsgType:      msgType,
		MsgExtraInfo: extraInfo,
		MsgContent:   content,
		MsgRecord:    record,
	}
}

func (r RawRecord) Convert() *Record {
	return &Record{
		SrcIp4:  util.IpIntToString(int(r.SrcIp4)),
		DstIp4:  util.IpIntToString(int(r.DstIp4)),
		SrcPort: int(r.SrcPort),
		DstPort: int(r.DstPort),
	}
}
