from flask import Flask
from flask import request
from flask import Response
import re
import requests


HOST = "192.168.152.157"

app = Flask(__name__) 
@app.route('/<path:path>', methods = ['POST', 'GET']) 
def index(path): 

    if request.method == 'GET': 
        return 'ok' 
 
    # check data 
    data = request.stream.read() 
    action = re.search(rb'<a:Action s:mustUnderstand="true">(.+?)</a:Action>', data) 
    assert action, "WinRM action not found" 
 
    data = data.decode()
    url = 'http://192.168.152.157:8000/' + path +'?'+ request.query_string.decode()
    print(url)
    r = requests.post(url, headers=request.headers, data=data)
 
    print(r.status_code)
    print(r.text)
    # make response 
    resp = Response(r.content, status=r.status_code) 
    for k, v in r.headers.items(): 
        if k in ['Content-Encoding', 'Content-Length', 'Transfer-Encoding']: 
            continue 
        resp.headers[k] = v 
 
    return resp 
 
app.run(host="127.0.0.1", port=8000)