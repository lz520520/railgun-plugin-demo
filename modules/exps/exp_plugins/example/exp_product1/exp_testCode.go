package exp_product1

import (
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/code_invoke"
	"github.com/lz520520/railgunlib/pkg/templates/code_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
)

type Exp_TESTCode struct {
	exp_templates.ExpTemplate
}

func (self *Exp_TESTCode) Attack_cmd1() (expResult exp_model.ExpResult) {
	// 默认配置
	dst, _ := JavaRuntimeExecEncode(self.MustGetStringParam("cmd"))
	self.EchoSuccessMsg(dst)

	return
}

// #####################编码转换模块生成#########################
func JavaRuntimeExecEncode(src string) (dst string, err error) {
	codeParams := []code_model.CodeParams{

		{
			CodeType:   "cmd",
			CodeName:   "JavaRuntimeExec",
			CodeMode:   "Encode",
			CodeStatus: true,
			CodeOptions: []code_model.CodeOption{

				{
					KeyName: "ps param",
					Value:   "-noni -w hidden -nop -ep b -e",
				},

				{
					KeyName: "alphabet",
					Value:   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
				},

				{
					KeyName: "type",
					Value:   "Bash",
				},
			},
		},

		{
			CodeType:   "char",
			CodeName:   "Url",
			CodeMode:   "Encode",
			CodeStatus: true,
			CodeOptions: []code_model.CodeOption{

				{
					KeyName: "unescape",
					Value:   "@*_+-./",
				},

				{
					KeyName: "type",
					Value:   "Query",
				},
			},
		},
	}
	return code_invoke.CodeInvoke(src, codeParams)
}

// #####################编码转换模块生成#########################

func init() {

	exp_register.ExpStructRegister(&Exp_TESTCode{}, "exp_testCode.yml")

}
