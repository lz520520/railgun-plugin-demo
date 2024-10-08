package exp_Struts2

import (
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
)

type Exp_S2_053 struct {
	exp_templates.ExpTemplate
}

func (s *Exp_S2_053) Attack_cmd1() (expResult exp_model.ExpResult) {
	return
}
func init() {
	exp_register.ExpStructRegister(&Exp_S2_053{}, "exp_S2_053.yml")
}
