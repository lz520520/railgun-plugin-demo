package exp_product1

import (
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"

	"github.com/lz520520/railgunlib/pkg/templates/code_invoke"
	"github.com/lz520520/railgunlib/pkg/templates/code_model"
)

type Exp_Plugin4 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_Plugin4) Attack_1() (expResult exp_model.ExpResult) {
	// 默认配置
	self.EchoSuccessMsg("cmd: %s", self.MustGetStringParam("cmd"))

	self.EchoSuccessMsg("key1: %s", self.MustGetStringParam("key"))
	//self.EchoSuccessMsg("file : %v", self.MustGetStringParam("file"))

	b, _ := Base64Encode("test1")
	self.EchoSuccessMsg("coder: %s", b)
	expResult.Status = true
	return
}

// #####################编码转换模块生成#########################
func Base64Encode(src string) (dst string, err error) {
	codeParams := []code_model.CodeParams{

		{
			CodeType:   "字符",
			CodeName:   "Base64",
			CodeMode:   "Encode",
			CodeStatus: true,
			CodeOptions: []code_model.CodeOption{

				{
					KeyName: "alphabet",
					Value:   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
				},

				{
					KeyName: "prefix",
					Value:   "",
				},
			},
		},

		{
			CodeType:   "字符",
			CodeName:   "Url",
			CodeMode:   "Encode",
			CodeStatus: true,
			CodeOptions: []code_model.CodeOption{

				{
					KeyName: "type",
					Value:   "Query",
				},

				{
					KeyName: "unescape",
					Value:   "@*_+-./",
				},
			},
		},
	}
	return code_invoke.CodeInvoke(src, codeParams)
}

// #####################编码转换模块生成#########################
func init() {
	exp_register.ExpStructRegister(&Exp_Plugin4{}, "exp_plugin4.yml")
}
