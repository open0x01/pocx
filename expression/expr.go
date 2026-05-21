package expression

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/dlclark/regexp2"
	"github.com/duke-git/lancet/cryptor"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	"github.com/iami317/hubur"
	"github.com/iami317/pocx/utils"
	"github.com/iami317/reverkit"
	"github.com/zan8in/oobadapter/pkg/oobadapter"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"math/rand"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type CELBuilder struct {
	reg ref.TypeRegistry
	// 声明
	envOptions []cel.EnvOption
	// 实现
	programOptions []cel.ProgramOption
}

func NewCELBuilder() *CELBuilder {
	reg, err := types.NewRegistry(
		&ConnType{},
		&AddrType{},
		&UrlType{},
		&HTTPRequestType{},
		&HTTPResponseType{},
		&NetworkRequestType{},
		&NetworkResponseType{},
		&ReverseType{},
		&OOB{},
	)
	// todo: must not be a error
	if err != nil {
		panic(err)
	}
	custom := &CELBuilder{}
	custom.envOptions = []cel.EnvOption{
		cel.CustomTypeAdapter(reg),
		cel.CustomTypeProvider(reg),
		cel.Container("expr"),
		//	类型注入
		//cel.Types(
		//),
		// 定义
		cel.Declarations(
			bcontainsDec,
			iContainsDec,
			bmatchDec,
			md5Dec,
			byteMd5Dec,
			bsubmatchDec,
			submatchDec,
			replaceAllDec,
			randomIntDec,
			randomLowercaseDec,
			printableDec,
			base64StringDec,
			base64BytesDec,
			base64DecodeStringDec,
			base64DecodeBytesDec,
			urlencodeStringDec,
			urlencodeBytesDec,
			urldecodeStringDec,
			urldecodeBytesDec,
			substrDec,
			sleepDec,
			faviconHashDec,
			versionCompareDec,
			bstartsWithDec,
			toUpperDec,
			toLowerDec,
			toUintStringDec,
			oobCheckDec,
			hexDecodeDec,
			repeatDec,
			nowDec,
			yearDec,
			monthDec,
			dayDec,
			ysoserialDec,
			aesCBCDec,
			rsaEncryptDec,
		),
	}
	// 实现
	custom.programOptions = []cel.ProgramOption{cel.Functions(
		iContainsFunc,
		bcontainsFunc,
		bmatchFunc,
		md5Func,
		byteMd5Func,
		submatchFunc,
		bsubmatchFunc,
		replaceFunc,
		randomIntFunc,
		randomLowercaseFunc,
		printableFunc,
		base64StringFunc,
		base64BytesFunc,
		base64DecodeStringFunc,
		base64DecodeBytesFunc,
		urlencodeStringFunc,
		urlencodeBytesFunc,
		urldecodeStringFunc,
		urldecodeBytesFunc,
		substrFunc,
		sleepFunc,
		faviconHashFunc,
		versionCompareFunc,
		bstartsWithFunc,
		toUpperFunc,
		toLowerFunc,
		toUintStringFunc,
		oobCheckFunc,
		hexDecodeFunc,
		repeatFunc,
		nowFunc,
		yearFunc,
		monthFunc,
		dayFunc,
		ysoserialFunc,
		aesCBCFunc,
		rsaEncryptFunc,
	)}
	custom.reg = reg
	return custom
}

var printableDec = decls.NewFunction("printable", decls.NewOverload("printable_string", []*exprpb.Type{decls.String}, decls.String))
var printableFunc = &functions.Overload{
	Operator: "printable_string",
	Unary: func(value ref.Val) ref.Val {
		s, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(s, "unexpected type '%v' passed to printable", s.Type())
		}

		clean := strings.Map(func(r rune) rune {
			if unicode.IsPrint(r) {
				return r
			}
			return -1
		}, string(s))

		return types.String(clean)
	},
}

var oobCheckDec = decls.NewFunction("oobCheck", decls.NewOverload("oobCheck_oob_string_int", []*exprpb.Type{decls.Any, decls.String, decls.Int}, decls.Bool))
var oobCheckFunc = &functions.Overload{
	Operator: "oobCheck_oob_string_int",
	Function: func(values ...ref.Val) ref.Val {
		oob, ok := values[0].Value().(*OOB)
		if !ok {
			return types.ValOrErr(values[0], "unexpected type '%v' passed to toUintString", values[0].Type())
		}
		filterType, ok := values[1].(types.String)
		if !ok {
			return types.ValOrErr(values[1], "unexpected type '%v' passed to toUintString", values[1].Type())
		}
		timeout, ok := values[2].(types.Int)
		if !ok {
			return types.ValOrErr(values[2], "unexpected type '%v' passed to toUintString", values[2].Type())
		}
		return types.Bool(oobCheck(oob, string(filterType), int64(timeout)))
	},
}

func oobCheck(oob *OOB, filterType string, timeout int64) bool {
	if oob == nil || len(oob.Filter) == 0 {
		return false
	}

	if len(filterType) == 0 {
		filterType = oobadapter.DnslogcnDNS
	}

	if timeout == 0 {
		timeout = 3
	}

	time.Sleep(time.Second * time.Duration(timeout))

	//result := OOB.ValidateResult(oobadapter.ValidateParams{
	//	Filter:     oob.Filter,
	//	FilterType: filterType,
	//})

	//return result.IsVaild
	return false
}

var ysoserialDec = decls.NewFunction("ysoserial", decls.NewOverload("ysoserial_string_string_string", []*exprpb.Type{decls.String, decls.String, decls.String}, decls.String))
var ysoserialFunc = &functions.Overload{
	Operator: "ysoserial_string_string_string",
	Function: func(values ...ref.Val) ref.Val {
		payload, ok := values[0].(types.String)
		if !ok {
			return types.ValOrErr(payload, "unexpected type '%v' passed to versionCompare", payload.Type())
		}
		command, ok := values[1].(types.String)
		if !ok {
			return types.ValOrErr(command, "unexpected type '%v' passed to versionCompare", command.Type())
		}
		encodeType, ok := values[2].(types.String)
		if !ok {
			return types.ValOrErr(encodeType, "unexpected type '%v' passed to versionCompare", encodeType.Type())
		}
		return types.String(hubur.GetYsoserial(string(payload), string(command), string(encodeType)))
	},
}

var yearDec = decls.NewFunction("year", decls.NewOverload("year_string", []*exprpb.Type{decls.Int}, decls.String))
var yearFunc = &functions.Overload{
	Operator: "year_string",
	Unary: func(value ref.Val) ref.Val {
		year := time.Now().Format("2006")
		return types.String(year)
	},
}

var monthDec = decls.NewFunction("month", decls.NewOverload("month_string", []*exprpb.Type{decls.Int}, decls.String))
var monthFunc = &functions.Overload{
	Operator: "month_string",
	Unary: func(value ref.Val) ref.Val {
		month := time.Now().Format("01")
		return types.String(month)
	},
}

var dayDec = decls.NewFunction("day", decls.NewOverload("day_string", []*exprpb.Type{decls.Int}, decls.String))
var dayFunc = &functions.Overload{
	Operator: "day_string",
	Unary: func(value ref.Val) ref.Val {
		day := time.Now().Format("02")
		return types.String(day)
	},
}

var nowDec = decls.NewFunction("now", decls.NewOverload("now_int", nil, decls.Int))
var nowFunc = &functions.Overload{
	Operator: "now_int",
	Function: func(values ...ref.Val) ref.Val {
		return types.Int(time.Now().Unix())
	},
}

var toUintStringDec = decls.NewFunction("toUintString", decls.NewInstanceOverload("toUintString_string_string", []*exprpb.Type{decls.Bytes}, decls.Int))
var toUintStringFunc = &functions.Overload{
	Operator: "toUintString_string_string",
	Function: func(values ...ref.Val) ref.Val {
		s1, ok := values[0].(types.String)
		s := string(s1)
		if !ok {
			return types.ValOrErr(s1, "unexpected type '%v' passed to toUintString", s1.Type())
		}
		direction, ok := values[1].(types.String)
		if !ok {
			return types.ValOrErr(direction, "unexpected type '%v' passed to toUintString", direction.Type())
		}
		if direction == "<" {
			s = utils.ReverseString(s)
		}
		if _, err := strconv.Atoi(s); err == nil {
			return types.String(s)
		} else {
			return types.NewErr("%v", err)
		}
	},
}

var toLowerDec = decls.NewFunction("toLower", decls.NewInstanceOverload("toLower_string", []*exprpb.Type{decls.Bytes}, decls.Int))
var toLowerFunc = &functions.Overload{
	Operator: "toLower_string",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to toUpper_string", value.Type())
		}

		return types.String(strings.ToLower(string(v)))
	},
}

var toUpperDec = decls.NewFunction("toUpper", decls.NewInstanceOverload("toUpper_string", []*exprpb.Type{decls.Bytes}, decls.Int))
var toUpperFunc = &functions.Overload{
	Operator: "toUpper_string",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to toUpper_string", value.Type())
		}

		return types.String(strings.ToUpper(string(v)))
	},
}

var bstartsWithDec = decls.NewFunction("bstartsWith", decls.NewInstanceOverload("bytes_bstartsWith_bytes", []*exprpb.Type{decls.Bytes, decls.Bytes}, decls.Bool))
var bstartsWithFunc = &functions.Overload{
	Operator: "bytes_bstartsWith_bytes",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		v1, ok := lhs.(types.Bytes)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to bstartsWith", lhs.Type())
		}
		v2, ok := rhs.(types.Bytes)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to bstartsWith", rhs.Type())
		}
		return types.Bool(bytes.HasPrefix(v1, v2))
	},
}

var bcontainsDec = decls.NewFunction("bcontains", decls.NewInstanceOverload("bytes_bcontains_bytes", []*exprpb.Type{decls.Bytes, decls.Bytes}, decls.Bool))
var bcontainsFunc = &functions.Overload{
	Operator: "bytes_bcontains_bytes",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		v1, ok := lhs.(types.Bytes)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to bcontains", lhs.Type())
		}
		v2, ok := rhs.(types.Bytes)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to bcontains", rhs.Type())
		}
		return types.Bool(bytes.Contains(v1, v2))
	},
}

// 判断s1是否包含s2, 忽略大小写
var iContainsDec = decls.NewFunction("icontains", decls.NewInstanceOverload("string_icontains_string", []*exprpb.Type{decls.String, decls.String}, decls.Bool))
var iContainsFunc = &functions.Overload{
	Operator: "string_icontains_string",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		v1, ok := lhs.(types.String)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to icontains", lhs.Type())
		}
		v2, ok := rhs.(types.String)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to icontains", rhs.Type())
		}
		return types.Bool(strings.Contains(strings.ToLower(string(v1)), strings.ToLower(string(v2))))
	},
}

// 截取字符串
var substrDec = decls.NewFunction("substr", decls.NewOverload("substr_string_int_int", []*exprpb.Type{decls.String, decls.Int, decls.Int}, decls.String))
var substrFunc = &functions.Overload{
	Operator: "substr_string_int_int",
	Function: func(values ...ref.Val) ref.Val {
		if len(values) == 3 {
			str, ok := values[0].(types.String)
			if !ok {
				return types.NewErr("invalid string to 'substr'")
			}
			start, ok := values[1].(types.Int)
			if !ok {
				return types.NewErr("invalid start to 'substr'")
			}
			length, ok := values[2].(types.Int)
			if !ok {
				return types.NewErr("invalid length to 'substr'")
			}
			runes := []rune(str)
			if start < 0 || length < 0 || int(start+length) > len(runes) {
				return types.NewErr("invalid start or length to 'substr'")
			}
			return types.String(runes[start : start+length])
		} else {
			return types.NewErr("too many arguments to 'substr'")
		}
	},
}

var replaceAllDec = decls.NewFunction("replaceAll", decls.NewOverload("replaceAll_string_string", []*exprpb.Type{decls.String, decls.String, decls.String}, decls.String))
var replaceFunc = &functions.Overload{
	Operator: "replaceAll_string_string",
	Function: func(values ...ref.Val) ref.Val {
		if len(values) != 3 {
			return types.NewErr("wrong arguments %v", values)
		}
		v1, ok := values[0].(types.String)
		if !ok {
			return types.NewErr("unexpected type '%v' passed to icontains", values[0].Type())
		}
		v2, ok := values[1].(types.String)
		if !ok {
			return types.NewErr("unexpected type '%v' passed to icontains", values[1].Type())
		}
		v3, ok := values[2].(types.String)
		if !ok {
			return types.NewErr("unexpected type '%v' passed to icontains", values[2].Type())
		}
		return types.String(strings.ReplaceAll(v1.Value().(string), v2.Value().(string), v3.Value().(string)))
	},
}

var aesCBCDec = decls.NewFunction("aesCBC", decls.NewOverload("aesCBC_string_string_string", []*exprpb.Type{decls.String, decls.String, decls.String}, decls.String))
var aesCBCFunc = &functions.Overload{
	Operator: "aesCBC_string_string_string",
	Function: func(values ...ref.Val) ref.Val {
		text, ok := values[0].(types.String)
		if !ok {
			return types.ValOrErr(text, "unexpected type '%v' passed to versionCompare", text.Type())
		}
		key, ok := values[1].(types.String)
		if !ok {
			return types.ValOrErr(key, "unexpected type '%v' passed to versionCompare", key.Type())
		}
		iv, ok := values[2].(types.String)
		if !ok {
			return types.ValOrErr(iv, "unexpected type '%v' passed to versionCompare", iv.Type())
		}

		plainText := hubur.PKCS5Padding([]byte(text), len(text))
		block, _ := aes.NewCipher([]byte(key))
		ciphertext := make([]byte, len(plainText))
		mode := cipher.NewCBCEncrypter(block, []byte(iv))
		mode.CryptBlocks(ciphertext, plainText)

		return types.String(ciphertext)
	},
}

var rsaEncryptDec = decls.NewFunction("rsaEncrypt", decls.NewOverload("rsaEncrypt_bytes_string", []*exprpb.Type{decls.Bytes, decls.String}, decls.Bytes))
var rsaEncryptFunc = &functions.Overload{
	Operator: "rsaEncrypt_bytes_string",
	Function: func(values ...ref.Val) ref.Val {
		datas, ok := values[0].(types.Bytes)
		if !ok {
			return types.ValOrErr(datas, "unexpected type '%v' passed to rsaEncrypt", datas.Type())
		}
		key, ok := values[1].(types.String)
		if !ok {
			return types.ValOrErr(key, "unexpected type '%v' passed to rsaEncrypt", key.Type())
		}
		return types.Bytes(cryptor.RsaEncrypt(datas, string(key)))
	},
}

// todo: implement
//var toUintString = decls.NewFunction()

// 使用正则表达式s1 来 匹配b1
var bmatchDec = decls.NewFunction("bmatches", decls.NewInstanceOverload("string_bmatch_bytes", []*exprpb.Type{decls.String, decls.Bytes}, decls.Bool))
var bmatchFunc = &functions.Overload{
	Operator: "string_bmatch_bytes",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		v1, ok := lhs.(types.String)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to bmatch", lhs.Type())
		}
		v2, ok := rhs.(types.Bytes)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to bmatch", rhs.Type())
		}
		ok, err := regexp.Match(string(v1), v2)
		if err != nil {
			return types.NewErr("%v", err)
		}
		return types.Bool(ok)
	},
}

var bsubmatchDec = decls.NewFunction("bsubmatch", decls.NewInstanceOverload("bsubmatch_bytes_map_string_tring", []*exprpb.Type{decls.String, decls.Bytes}, decls.NewMapType(decls.String, decls.String)))
var bsubmatchFunc = &functions.Overload{
	Operator: "bsubmatch_bytes_map_string_tring",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		v1, ok := lhs.(types.String)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to bmatch", lhs.Type())
		}

		v2, ok := rhs.(types.Bytes)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to bmatch", rhs.Type())
		}
		rexp, err := regexp2.Compile(v1.Value().(string), regexp2.RE2)
		if err != nil {
			return types.NewErr("failed to compile regexp: %s, %s", v1.Value(), err)
		}

		match, err := rexp.FindRunesMatch(bytes.Runes(v2.Value().([]byte)))
		if err != nil {
			return types.NewErr("find substring: %s", err)
		}

		m := make(map[string]string)
		if match != nil {
			for _, group := range match.Groups() {
				m[group.Name] = group.Capture.String()
			}
		}
		return types.NewStringStringMap(types.DefaultTypeAdapter, m)
	},
}

var submatchDec = decls.NewFunction("submatch", decls.NewInstanceOverload("submatch_string_map_string_tring", []*exprpb.Type{decls.String, decls.String}, decls.NewMapType(decls.String, decls.String)))
var submatchFunc = &functions.Overload{
	Operator: "submatch_string_map_string_tring",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		v1, ok := lhs.(types.String)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to bmatch", lhs.Type())
		}

		v2, ok := rhs.(types.String)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to bmatch", rhs.Type())
		}
		rexp, err := regexp2.Compile(v1.Value().(string), regexp2.RE2)
		if err != nil {
			return types.NewErr("failed to compile regexp: %s, %s", v1.Value(), err)
		}

		match, err := rexp.FindStringMatch(v2.Value().(string))
		if err != nil {
			return types.NewErr("find substring: %s", err)
		}
		m := make(map[string]string)
		if match != nil {
			for _, group := range match.Groups() {
				m[group.Name] = group.Capture.String()
			}
		}
		return types.NewStringStringMap(types.DefaultTypeAdapter, m)
	},
}

// 字符串的 md5
var md5Dec = decls.NewFunction("md5", decls.NewOverload("md5_string", []*exprpb.Type{decls.String}, decls.String))
var md5Func = &functions.Overload{
	Operator: "md5_string",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to md5_string", value.Type())
		}
		return types.String(fmt.Sprintf("%x", md5.Sum([]byte(v))))
	},
}

// 字节的 md5
var byteMd5Dec = decls.NewFunction("byte_md5", decls.NewOverload("byte_md5_string", []*exprpb.Type{decls.Bytes}, decls.String))
var byteMd5Func = &functions.Overload{
	Operator: "byte_md5_string",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.Bytes)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to byte_md5_string", value.Type())
		}
		return types.String(fmt.Sprintf("%x", md5.Sum(v)))
	},
}

// 将字符串进行 base64 编码
var base64StringDec = decls.NewFunction("base64", decls.NewOverload("base64_string", []*exprpb.Type{decls.String}, decls.String))
var base64StringFunc = &functions.Overload{
	Operator: "base64_string",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to base64_string", value.Type())
		}
		return types.String(base64.StdEncoding.EncodeToString([]byte(v)))
	},
}

// 将bytes进行 base64 编码
var base64BytesDec = decls.NewFunction("base64", decls.NewOverload("base64_bytes", []*exprpb.Type{decls.Bytes}, decls.String))
var base64BytesFunc = &functions.Overload{
	Operator: "base64_bytes",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.Bytes)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to base64_bytes", value.Type())
		}
		return types.String(base64.StdEncoding.EncodeToString(v))
	},
}

// 将字符串进行 base64 解码
var base64DecodeStringDec = decls.NewFunction("base64Decode", decls.NewOverload("base64Decode_string", []*exprpb.Type{decls.String}, decls.String))
var base64DecodeStringFunc = &functions.Overload{
	Operator: "base64Decode_string",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to base64Decode_string", value.Type())
		}
		decodeBytes, err := base64.StdEncoding.DecodeString(string(v))
		if err != nil {
			return types.NewErr("%v", err)
		}
		return types.String(decodeBytes)
	},
}

// 将bytes进行 base64 编码
var base64DecodeBytesDec = decls.NewFunction("base64Decode", decls.NewOverload("base64Decode_bytes", []*exprpb.Type{decls.Bytes}, decls.String))
var base64DecodeBytesFunc = &functions.Overload{
	Operator: "base64Decode_bytes",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.Bytes)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to base64Decode_bytes", value.Type())
		}
		decodeBytes, err := base64.StdEncoding.DecodeString(string(v))
		if err != nil {
			return types.NewErr("%v", err)
		}
		return types.String(decodeBytes)
	},
}

// 将字符串进行 urlencode 编码
var urlencodeStringDec = decls.NewFunction("urlencode", decls.NewOverload("urlencode_string", []*exprpb.Type{decls.String}, decls.String))
var urlencodeStringFunc = &functions.Overload{
	Operator: "urlencode_string",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to urlencode_string", value.Type())
		}
		return types.String(url.QueryEscape(string(v)))
	},
}

// 将bytes进行 urlencode 编码
var urlencodeBytesDec = decls.NewFunction("urlencode", decls.NewOverload("urlencode_bytes", []*exprpb.Type{decls.Bytes}, decls.String))
var urlencodeBytesFunc = &functions.Overload{
	Operator: "urlencode_bytes",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.Bytes)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to urlencode_bytes", value.Type())
		}
		return types.String(url.QueryEscape(string(v)))
	},
}

// 将bytes进行 hash 编码
var faviconHashDec = decls.NewFunction("faviconHash", decls.NewInstanceOverload("favicon_hash", []*exprpb.Type{decls.Bytes}, decls.Int))
var faviconHashFunc = &functions.Overload{
	Operator: "favicon_hash",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.Bytes)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to urlencode_bytes", value.Type())
		}
		hash := types.Int(hubur.FaviconHash(v))
		return hash
	},
}

// 版本比较
var versionCompareDec = decls.NewFunction("versionCompare", decls.NewOverload("versionCompare_string_string_string", []*exprpb.Type{decls.String, decls.String, decls.String}, decls.Bool))
var versionCompareFunc = &functions.Overload{
	Operator: "versionCompare_string_string_string",
	Function: func(values ...ref.Val) ref.Val {
		if len(values) != 3 {
			return types.Bool(false)
		}
		v1, ok := values[0].(types.String)
		if !ok {
			return types.ValOrErr(v1, "unexpected type '%v' passed to versionCompare", v1.Type())
		}
		operator, ok := values[1].(types.String)
		if !ok {
			return types.ValOrErr(operator, "unexpected type '%v' passed to versionCompare", operator.Type())
		}
		v2, ok := values[2].(types.String)
		if !ok {
			return types.ValOrErr(v2, "unexpected type '%v' passed to versionCompare", v2.Type())
		}

		return types.Bool(utils.Compare(string(v1), string(operator), string(v2)))
	},
}

// 将字符串进行 urldecode 解码
var urldecodeStringDec = decls.NewFunction("urldecode", decls.NewOverload("urldecode_string", []*exprpb.Type{decls.String}, decls.String))
var urldecodeStringFunc = &functions.Overload{
	Operator: "urldecode_string",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to urldecode_string", value.Type())
		}
		decodeString, err := url.QueryUnescape(string(v))
		if err != nil {
			return types.NewErr("%v", err)
		}
		return types.String(decodeString)
	},
}

// 将 bytes 进行 urldecode 解码
var urldecodeBytesDec = decls.NewFunction("urldecode", decls.NewOverload("urldecode_bytes", []*exprpb.Type{decls.Bytes}, decls.String))
var urldecodeBytesFunc = &functions.Overload{
	Operator: "urldecode_bytes",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.Bytes)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to urldecode_bytes", value.Type())
		}
		decodeString, err := url.QueryUnescape(string(v))
		if err != nil {
			return types.NewErr("%v", err)
		}
		return types.String(decodeString)
	},
}

var randomIntDec = decls.NewFunction("randomInt", decls.NewOverload("randomInt_int_int", []*exprpb.Type{decls.Int, decls.Int}, decls.Int))
var randomIntFunc = &functions.Overload{
	Operator: "randomInt_int_int",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		from, ok := lhs.(types.Int)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to randomInt", lhs.Type())
		}
		to, ok := rhs.(types.Int)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to randomInt", rhs.Type())
		}
		min, max := int(from), int(to)
		return types.Int(rand.Intn(max-min) + min)
	},
}

// 指定长度的小写字母组成的随机字符串
var randomLowercaseDec = decls.NewFunction("randomLowercase", decls.NewOverload("randomLowercase_int", []*exprpb.Type{decls.Int}, decls.String))
var randomLowercaseFunc = &functions.Overload{
	Operator: "randomLowercase_int",
	Unary: func(value ref.Val) ref.Val {
		n, ok := value.(types.Int)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to randomLowercase", value.Type())
		}
		return types.String(hubur.RandLowerLetter(int(n)))
	},
}

// 将16进制字符串解码为字符串
var hexDecodeDec = decls.NewFunction("hexDecode", decls.NewOverload("hexDecode_string", []*exprpb.Type{decls.String}, decls.String))
var hexDecodeFunc = &functions.Overload{
	Operator: "hexDecode_string",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to hexDecode_string", value.Type())
		}
		dst := make([]byte, hex.DecodedLen(len(v)))
		n, err := hex.Decode(dst, []byte(v))
		if err != nil {
			return types.ValOrErr(value, "unexpected type '%s' passed to hexdecode_string", err.Error())
		}
		return types.String(string(dst[:n]))
	},
}
var repeatDec = decls.NewFunction("repeat", decls.NewOverload("repeat_string_int", []*exprpb.Type{decls.String, decls.Int}, decls.String))
var repeatFunc = &functions.Overload{
	Operator: "repeat_string_int",
	Binary: func(v1 ref.Val, v2 ref.Val) ref.Val {
		str, ok := v1.(types.String)
		if !ok {
			return types.ValOrErr(v1, "unexpected type '%v' passed to randomLowercase", v1.Type())
		}
		count, ok := v2.(types.Int)
		if !ok {
			return types.ValOrErr(v2, "unexpected type '%v' passed to randomLowercase", v2.Type())
		}

		return types.String(strings.Repeat(string(str), int(count)))
	},
}

// 暂停执行等待指定的秒数
var sleepDec = decls.NewFunction("sleep", decls.NewOverload("sleep_int", []*exprpb.Type{decls.Int}, decls.Bool))
var sleepFunc = &functions.Overload{
	Operator: "sleep_int",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.Int)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to sleep", value.Type())
		}
		time.Sleep(time.Duration(v) * time.Second)
		return types.Bool(true)
	},
}

func (c *CELBuilder) AddDeclarations(decs ...*exprpb.Decl) *CELBuilder {
	c.envOptions = append(c.envOptions, cel.Declarations(decs...))
	return c
}

func (c *CELBuilder) AddProgramOptions(options ...cel.ProgramOption) *CELBuilder {
	c.programOptions = append(c.programOptions, options...)
	return c
}

func (c *CELBuilder) WithHTTPType() *CELBuilder {
	c.envOptions = append(c.envOptions, cel.Declarations(
		decls.NewVar("request", decls.NewObjectType("expr.HTTPRequestType")),
		decls.NewVar("response", decls.NewObjectType("expr.HTTPResponseType")),
	))
	return c
}

func (c *CELBuilder) NewReverse(client *reverkit.Client, source string) ref.Val {
	unit := client.NewUnit()
	unit.OnVisit(func(event *reverkit.Event) error {
		return nil
	})
	u := unit.GetVisitURL()
	urlParsed, err := url.Parse(u)
	if err != nil {
		return types.NewErr("can't parse url, %s", err)
	}
	oldHost := urlParsed.Hostname()
	urlParsed.Host = strings.ReplaceAll(urlParsed.Host, oldHost, source)
	reverseUrl := UrlType{
		Scheme:   urlParsed.Scheme,
		Domain:   urlParsed.Hostname(),
		Host:     urlParsed.Host,
		Port:     urlParsed.Port(),
		Path:     urlParsed.Path,
		Query:    urlParsed.RawQuery,
		Fragment: urlParsed.Fragment,
	}
	recvType := &ReverseType{
		Rmi:     unit.GetRmiURL(),
		Ldap:    unit.GetLdapURL(),
		Url:     &reverseUrl,
		GroupId: unit.GroupId(),
	}
	recvType.Rmi = strings.ReplaceAll(recvType.Rmi, oldHost, source)
	recvType.Ldap = strings.ReplaceAll(recvType.Ldap, oldHost, source)
	val := c.reg.NativeToValue(recvType)
	return val
}

func (c *CELBuilder) WithReverseType(client *reverkit.Client) *CELBuilder {
	reverseType := decls.NewObjectType("expr.ReverseType")
	c.envOptions = append(c.envOptions, cel.Declarations(
		decls.NewFunction("newReverse", decls.NewOverload("newReverse_default", []*exprpb.Type{}, reverseType)),
		decls.NewFunction("wait", decls.NewInstanceOverload("reverse_wait_int", []*exprpb.Type{reverseType, decls.Int}, decls.Bool)),
	))

	var newReverseFunc = &functions.Overload{
		Operator: "newReverse_default",
		Function: func(values ...ref.Val) ref.Val {
			unit := client.NewUnit()
			unit.OnVisit(func(event *reverkit.Event) error {
				return nil
			})
			u := unit.GetVisitURL()
			urlParsed, err := url.Parse(u)
			if err != nil {
				return types.NewErr("can't parse url, %s", err)
			}
			reverseUrl := UrlType{
				Scheme:   urlParsed.Scheme,
				Domain:   urlParsed.Hostname(),
				Host:     urlParsed.Host,
				Port:     urlParsed.Port(),
				Path:     urlParsed.Path,
				Query:    urlParsed.RawQuery,
				Fragment: urlParsed.Fragment,
			}

			recvType := &ReverseType{
				Rmi:     unit.GetRmiURL(),
				Ldap:    unit.GetLdapURL(),
				Url:     &reverseUrl,
				GroupId: unit.GroupId(),
			}
			val := c.reg.NativeToValue(recvType)
			return val
		},
	}
	var reverseWaitFunc = &functions.Overload{
		Operator: "reverse_wait_int",
		Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
			reverType, ok := lhs.Value().(*ReverseType)
			if !ok {
				return types.NewErr("bad type of lhs %s", lhs.Type())
			}
			seconds, ok := rhs.(types.Int)
			if !ok {
				return types.NewErr("bad arg type of reverse wait %s", rhs.Type())
			}
			group := client.Resolve(reverType.GroupId)
			if group == nil {
				return types.NewErr("group not found in db, %s", reverType.GroupId)
			}
			if group.Wait(time.Duration(seconds)*time.Second) != nil {
				return types.Bool(false)
			} else {
				return types.Bool(true)
			}
		},
	}
	c.programOptions = append(c.programOptions, cel.Functions(
		newReverseFunc,
		reverseWaitFunc,
	))
	return c
}

func (c *CELBuilder) WithOobType(client *oobadapter.OOBAdapter) *CELBuilder {
	oobType := decls.NewObjectType("expr.OOB")
	c.envOptions = append(c.envOptions, cel.Declarations(
		decls.NewFunction("oob", decls.NewOverload("oob_default", []*exprpb.Type{}, oobType)),
	))

	var newReverseFunc = &functions.Overload{
		Operator: "oob_default",
		Function: func(values ...ref.Val) ref.Val {
			return c.reg.NativeToValue(values)
		},
	}
	c.programOptions = append(c.programOptions, cel.Functions(
		newReverseFunc,
	))
	return c
}

func (c *CELBuilder) WithNetworkType() *CELBuilder {
	c.envOptions = append(c.envOptions, cel.Declarations(
		decls.NewVar("request", decls.NewObjectType("expr.NetworkRequestType")),
		decls.NewVar("response", decls.NewObjectType("expr.NetworkResponseType")),
	))
	return c
}

func (c *CELBuilder) WithSshType() *CELBuilder {
	c.envOptions = append(c.envOptions, cel.Declarations(
		//decls.NewVar("request", decls.NewObjectType("expr.NetworkRequestType")),
		decls.NewVar("response", decls.NewObjectType("expr.SshResponseType")),
	))
	return c
}

func (c *CELBuilder) Build() (*cel.Env, error) {
	return cel.NewEnv(cel.Lib(c))
}

func (c *CELBuilder) BuildAndCompile(expression string, boolRequired bool) (cel.Program, error) {
	env, err := c.Build()
	if err != nil {
		return nil, err
	}
	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compile error, %v", issues.Err())
	}
	if boolRequired && ast.ResultType().GetPrimitive() != exprpb.Type_BOOL {
		return nil, fmt.Errorf("ast result is not bool")
	}
	return env.Program(ast, cel.EvalOptions(cel.OptOptimize))
}

// CompileOptions implements cel.Library
func (c *CELBuilder) CompileOptions() []cel.EnvOption {
	return c.envOptions
}

// ProgramOptions implements cel.Library
func (c *CELBuilder) ProgramOptions() []cel.ProgramOption {
	return c.programOptions
}

func Evaluate(env *cel.Env, expression string, params map[string]interface{}) (ref.Val, error) {
	ast, iss := env.Compile(expression)
	if iss.Err() != nil {
		return nil, iss.Err()
	}
	prg, err := env.Program(ast)
	if err != nil {
		return nil, err
	}
	out, _, err := prg.Eval(params)
	if err != nil {
		return nil, err
	}
	return out, nil
}
