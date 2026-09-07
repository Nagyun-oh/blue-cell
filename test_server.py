"""Integration tests: temporary database, local fake LLM, no real credentials."""
import importlib.util, json, os, tempfile, threading, unittest, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

class Model(BaseHTTPRequestHandler):
    records=[]
    def log_message(self,*a): pass
    def do_POST(self):
        p=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.records.append(p)
        data=json.loads(p['messages'][1]['content'])
        answer=data.get('allowed_response') or ('RECOVERY' if 'password' in data.get('text','') else 'OTHER')
        b=json.dumps({'choices':[{'message':{'content':answer}}]}).encode()
        self.send_response(200);self.end_headers();self.wfile.write(b)

class Flow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        os.environ.update(DATABASE_PATH=cls.tmp.name+'/test.db',ADMIN_PASSWORD='test-admin-password',USER_PASSWORD='test-user-password',LAB_XSS='1',TRUSTED_PROXY_IPS='127.0.0.1')
        cls.model=ThreadingHTTPServer(('127.0.0.1',0),Model)
        os.environ['LLM_API_URL']=f'http://127.0.0.1:{cls.model.server_port}/chat/completions'
        spec=importlib.util.spec_from_file_location('blue',Path(__file__).with_name('server.py')); cls.app=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.app)
        cls.app.initialize();cls.web=ThreadingHTTPServer(('127.0.0.1',0),cls.app.Handler)
        cls.url=f'http://127.0.0.1:{cls.web.server_port}';cls.app.ORIGIN=cls.url
        for s in (cls.model,cls.web): threading.Thread(target=s.serve_forever,daemon=True).start()
    @classmethod
    def tearDownClass(cls):
        for s in (cls.web,cls.model):s.shutdown();s.server_close()
        cls.tmp.cleanup()
    def request(self,path,data=None,cookie='',ip='203.0.113.10',origin=True):
        h={'Content-Type':'application/json','X-Real-IP':ip,'Cookie':cookie}
        if origin:h['Origin']=self.url
        req=urllib.request.Request(self.url+path,json.dumps(data).encode() if data is not None else None,h)
        try:r=urllib.request.urlopen(req)
        except urllib.error.HTTPError as e:r=e
        raw=r.read().decode();body=json.loads(raw) if r.headers.get('Content-Type','').startswith('application/json') else raw
        return r.status,body,r.headers.get('Set-Cookie','').split(';')[0]
    def test_full_flow(self):
        self.assertEqual(self.request('/api/register',{'username':'red','email':'red@example.test','password':'red-password-123'})[0],200)
        admin=self.request('/api/login',{'username':'admin','password':'test-admin-password'})[2]
        user=self.request('/api/login',{'username':'user','password':'test-user-password'})[2]
        red=self.request('/api/login',{'username':'red','password':'red-password-123'})[2]
        self.assertEqual(self.request('/api/me',cookie=admin)[1]['role'],'admin')
        self.assertEqual(self.request('/api/me',cookie=admin,ip='203.0.113.20')[0],401)
        self.assertEqual(self.request('/api/inquiries',{'title':'Exercise','body':'<b>stored</b>'},red)[0],200)
        id=self.request('/api/inquiries',cookie=red)[1][0]['id']
        self.assertEqual(self.request(f'/inquiry/{id}',cookie=user)[0],404)
        self.assertIn('<b>stored</b>',self.request(f'/inquiry/{id}',cookie=admin)[1])
        self.assertEqual(self.request('/api/logout',{},admin,origin=False)[0],403)
        self.assertEqual(self.request('/api/reset',{'token':'bad','password':'new-password-123'})[0],400)
        chat=self.request('/api/chat',{'message':'start','restart':True})[2]
        for msg in ['lost password','user']:
            self.assertEqual(self.request('/api/chat',{'message':msg},chat)[0],200)
        before=len(Model.records)
        self.assertIn('일치하지',self.request('/api/chat',{'message':'wrong@example.test'},chat)[1]['reply'])
        self.assertEqual(before,len(Model.records))
        chat=self.request('/api/chat',{'message':'start','restart':True})[2]
        for msg in ['lost password','user']:
            self.request('/api/chat',{'message':msg},chat)
        reply=self.request('/api/chat',{'message':'user@example.test'},chat)[1]['reply']
        token=reply.split(': ')[1]
        self.assertEqual(Model.records[-1]['model'],'llama-3.2-3b-instruct')
        prompt=json.loads(Model.records[-1]['messages'][1]['content'])
        self.assertEqual((prompt['username'],prompt['email']),('user','user@example.test'))
        self.assertEqual(self.request('/api/reset',{'token':token,'password':'new-password-123'})[0],200)
        self.assertEqual(self.request('/api/reset',{'token':token,'password':'new-password-456'})[0],400)
        self.assertEqual(self.request('/api/me',cookie=user)[0],401)
        self.assertEqual(self.request('/api/login',{'username':'user','password':'new-password-123'})[0],200)
        chat=self.request('/api/chat',{'message':'start','restart':True})[2]
        self.assertEqual(self.request('/api/chat',{'message':'business hours'},chat)[1]['reply'],'상담챗봇의 처리 사항이 아닙니다')
        self.assertEqual(self.request('/api/register',{'username':"' OR 1=1 --",'email':'a@b.test','password':'abcdefghijkl'})[0],400)
        self.assertEqual(self.request('/')[0],200)

if __name__=='__main__':unittest.main(verbosity=2)
