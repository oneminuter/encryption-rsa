# encryption-rsa
js rsa 分段加解密，支持中文 &amp; 任意 秘钥长度

前端代码位于 index.html 中

后端 Go 使用 github.com/wenzhenxi/gorsa 加密返回

简单示例代码
```
package encryption

import (
	"github.com/gin-gonic/gin"
	"github.com/wenzhenxi/gorsa"
	"oneminuter/utils"
)

type Rsa struct {
	PvK     string `json:"pv_k"`
	EncText string `json:"enc_text"`
}

func rsa(c *gin.Context) {
    // 生成一个 2048 字节的 rsa 秘钥
	pubKey, privKey, err := utils.GenerateRSAKey(2048)
	if err != nil {
		log.Println("GenerateRSAKey error err=%s", err.Error())
		c.String(http.StatusOK, "服务错误")
		return
	}

	var text = "begin hello 这是中文 hellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohello 这是中文hello 这是中文 hellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohello 这是中文hello 这是中文 hellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohello 这是中文hello 这是中文 hellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohello 这是中文hello 这是中文 hellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohello 这是中文hello 这是中文 hellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohello 这是中文 end"

	encText, err := gorsa.PublicEncrypt(text, string(pubKey))
	if err != nil {
		log.Println("gorsa.PublicEncrypt error err=%s", err.Error())
		c.String(http.StatusOK, "服务错误")
		return
	}

	lib.ReplyOk(c, Rsa{
		PvK:     string(privKey),
		EncText: encText,
	})
	return
}
```

utils.GenerateRSAKey(2048) 对应调用的方法
```
package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// GenerateKey函数使用随机数据生成器random生成一对具有指定字位数的RSA密钥
func GenerateRSAKey(bits int) (puk, pvk []byte, err error) {
	//Reader是一个全局、共享的密码用强随机数生成器
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	//保存私钥
	//通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
	X509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	//使用pem格式对x509输出的内容进行编码

	//构建一个pem.Block结构体对象
	privateBlock := pem.Block{Type: "RSA Private Key", Bytes: X509PrivateKey}

	privateKeyByte := pem.EncodeToMemory(&privateBlock)

	//获取公钥的数据
	publicKey := privateKey.PublicKey

	//X509对公钥编码
	X509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return nil, nil, err
	}

	//pem格式编码
	//创建一个pem.Block结构体对象
	publicBlock := pem.Block{Type: "RSA Public Key", Bytes: X509PublicKey}

	publicKeyByte := pem.EncodeToMemory(&publicBlock)

	return publicKeyByte, privateKeyByte, nil
}
```