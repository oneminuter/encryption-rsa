# encryption-rsa
js rsa 分段加解密，支持中文 &amp; 任意 秘钥长度

前端代码位于 rsa.html 中

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


## go gzip 压缩，js 前端解压缩
后端：gzip 压缩 > base64 编码 > 前端接收 > base64 解码 > pako 解压

注意：go 后端 gzip 压缩的过程中，Write 之后一定要及时 Close，不能 defer， 这样才能 flush
```
import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"net/http"
	"oneminuter/lib"
	"oneminuter/lib/olog"
	"oneminuter/utils"
)

func gzipcompress(c *gin.Context) {

	var text = "hello world"

	// 压缩
	var b bytes.Buffer
	writer := gzip.NewWriter(&b)
	_, err := writer.Write(utils.String2bytes(text))
	if err != nil {
		olog.ErrorC(c, "gzip writer write error. err=%s", err.Error())
		lib.ReplyFailedWithCodeAndDetail(c, lib.CodeSrv, "gzip writer write error")
		return
	}
	// gzip压缩的过程中，Write之后一定要及时Close，不能defer， 这样才能flush
	writer.Close()

	marshal, _ := json.Marshal(writer.Header)
	fmt.Println(string(marshal))

	err = writer.Flush()
	if err != nil {
		olog.ErrorC(c, "gzip writer flush error. err=%s", err.Error())
		lib.ReplyFailedWithCodeAndDetail(c, lib.CodeSrv, "gzip writer flush error")
		return
	}

	fmt.Println(b.Len())
	fmt.Println(b.Bytes())

	toString := base64.StdEncoding.EncodeToString(b.Bytes())
	fmt.Println(toString)

	// 解压
	rdata := bytes.NewReader(b.Bytes())
	r, _ := gzip.NewReader(rdata)
	s, _ := ioutil.ReadAll(r)
	fmt.Println(string(s))

	c.String(http.StatusOK, toString)
	return
}
```

### 关于前端接收后端二进制数据流
```
// 如果接收 arraybuffer 就不能使用 jquery 的 ajax, 得用原生的 XMLHttpRequest
// 猜测可能是：jquery 接收返回内容会默认做一次 parse 导致
// 如果坚持要用 jquery 的 ajax，可以后端转为 base64 编码，前端解码之后再解压
```
前端代码示例
```
// 前端压缩，后端解压， 前端只能用 pako.gzip 压缩，后端才能解压
// 使用  pako.deflate 压缩，后端对应 zlib 解压，不是 gzip 解压
function gzip() {
    let comp = pako.gzip("hello world");
    
	// 使用  pako.deflate 压缩，后端对应 zlib 解压，不是 gzip 解压
    // let result = pako.deflate("hello world");
    // console.log(result);
    // console.log(pako.inflate(result, { to: 'string' }));
   
    var oReq = new XMLHttpRequest();
    oReq.open("POST", "http://localhost:9147/encryption/ungzip", true);
    oReq.onload = function (oEvent) {
        console.log(oReq.response)
    };

    oReq.send(comp);
    // oReq.send(result);
}
```

### 前端压缩，后端解压
```
// gzip: 前端压缩，后端解压， 前端用 pako.gzip 压缩，后端才能解压
// 使用 pako.deflate 压缩，后端对应 zlib 解压，不是 gzip 解压
```