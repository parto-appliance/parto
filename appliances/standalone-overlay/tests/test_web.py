"""Exercise HTTP authentication, CSRF, exchange downloads and role privacy."""
import http.client
import importlib.util
import json
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/'src'))
spec=importlib.util.spec_from_file_location('parto_web',ROOT/'appliances/standalone-overlay/parto-web.py')
web=importlib.util.module_from_spec(spec);spec.loader.exec_module(web)

class WebTests(unittest.TestCase):
    def setUp(self):
        web.SESSIONS.clear();web.FAILURES.clear()
        self.server=web.Server(('::1',0),web.Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.port=self.server.server_port;self.cookie='';self.csrf=''
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join()
    def request(self,path,value=None,origin=True,csrf=True):
        c=http.client.HTTPConnection('::1',self.port,timeout=3)
        headers={'Host':f'[::1]:{self.port}','Cookie':self.cookie}
        if value is not None:
            headers['Content-Type']='application/json'
            if origin:headers['Origin']='https://'+headers['Host']
            if csrf:headers['X-CSRF-Token']=self.csrf
        c.request('GET' if value is None else 'POST','/api/'+path,body=None if value is None else json.dumps(value),headers=headers)
        r=c.getresponse();data=json.loads(r.read());cookie=r.getheader('Set-Cookie')
        if cookie:self.cookie=cookie.split(';')[0]
        c.close();return r.status,data,cookie
    def login(self):
        with patch.object(web,'helper',return_value={'ok':True}):
            status,data,cookie=self.request('login',{'username':'admin','password':'test-only'})
        self.assertEqual(status,200);self.csrf=data['csrf']
        self.assertIn('Secure',cookie);self.assertIn('HttpOnly',cookie);self.assertIn('SameSite=Strict',cookie)
    def test_status_requires_login_and_mutations_require_origin_csrf(self):
        self.assertEqual(self.request('state')[0],401)
        self.login()
        with patch.object(web,'helper') as helper:
            self.assertEqual(self.request('apply',{},origin=False)[0],403)
            self.assertEqual(self.request('apply',{},csrf=False)[0],401)
            helper.assert_not_called()
    def test_rate_limit_rejects_sixth_bad_login(self):
        with patch.object(web,'helper',side_effect=ValueError('Invalid')):
            for _ in range(5):self.assertEqual(self.request('login',{'username':'admin','password':'bad'})[0],401)
            self.assertEqual(self.request('login',{'username':'admin','password':'bad'})[0],429)
    def test_login_uses_only_admin_identity(self):
        with patch.object(web,'helper') as helper:
            self.assertEqual(self.request('login',{'username':'root','password':'test'})[0],401);helper.assert_not_called()
    def test_unsupported_action_never_calls_helper(self):
        self.login()
        with patch.object(web,'helper') as helper:
            self.assertEqual(self.request('shell',{'command':'id'})[0],404);helper.assert_not_called()
    def test_unencrypted_download_and_site_filename(self):
        self.login()
        with patch.object(web,'helper',side_effect=[{'role':'spoke','label':'North / Site'}, {'file':{'body':{'kind':'standalone-spoke'}}},{'ok':True}]):
            status,data,_=self.request('export',{'encrypt':False})
        self.assertEqual(status,200);self.assertEqual(data['filename'],'North - Site-request.json');self.assertIn('file',data)
    def test_import_requires_trust_confirmation(self):
        self.login()
        with patch.object(web.exchange,'inspect_peer',return_value={'fingerprint':'abc'}),patch.object(web,'helper') as helper:
            self.assertEqual(self.request('import',{'file':{},'trusted':False})[0],400);helper.assert_not_called()
    def test_logout_invalidates_session(self):
        self.login();self.assertEqual(self.request('logout',{})[0],200);self.assertEqual(self.request('state')[0],401)

if __name__=='__main__':unittest.main()

class ProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0,str(ROOT/'appliances/parto-vm/runtime'))
        spec=importlib.util.spec_from_file_location('web_root_test',ROOT/'appliances/standalone-overlay/standalone-root.py')
        cls.root=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.root)
    def test_spoke_projection_excludes_other_spokes(self):
        r=self.root
        def site(node,role):
            return {'node':node,'slot':{'hub':1,'self':2,'other':3}[node],'settings':{'role':role,'label':node,'wan':'eth0','lans':['eth1'],'prefixes':[],'endpoint':''}}
        roster=[site('hub','hub'),site('self','spoke'),site('other','spoke')]
        info={'ok':True,'role':'spoke','peers':[{'node':p['node'],'role':p['settings']['role']} for p in roster]}
        with patch.object(r,'STATE') as path:
            path.exists.return_value=True
            with patch.object(r,'interface_addresses',return_value=[]),patch.object(r,'read',return_value={'node':'self','settings':{'role':'spoke'}}),patch.object(r,'body',return_value={'roster':roster}),patch.object(r,'operate',side_effect=[info,{'ok':True}]):
                answer=r.web_info()
        self.assertEqual({p['node'] for p in answer['peers']},{'hub','self'})
        self.assertEqual({p['id'] for p in answer['topology']['sites']},{'hub','self'})
        self.assertNotIn('other',json.dumps(answer))
    def test_addresses_exclude_loopback_down_and_link_local(self):
        rows=[{'ifname':'lo','flags':['UP'],'addr_info':[{'local':'127.0.0.1','prefixlen':8,'family':'inet','scope':'host'}]}, {'ifname':'eth0','flags':['UP'],'addr_info':[{'local':'192.0.2.2','prefixlen':24,'family':'inet','scope':'global'},{'local':'fe80::1','prefixlen':64,'family':'inet6','scope':'link'}]}, {'ifname':'eth1','flags':[],'addr_info':[]}]
        with patch.object(self.root.subprocess,'check_output',return_value=json.dumps(rows)):
            self.assertEqual(self.root.interface_addresses(),[{'name':'eth0','up':True,'addresses':['192.0.2.2/24']}])


class PackagedWorkflowTests(unittest.TestCase):
    def test_staged_helpers_match_runtime_allowlist(self):
        import tempfile
        sys.path.insert(0,str(ROOT/'appliances/parto-vm/runtime'))
        modules=[]
        for name,file in [('pin_stage','stage.py'),('pin_root','standalone-root.py')]:
            spec=importlib.util.spec_from_file_location(name,ROOT/'appliances/standalone-overlay'/file)
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);modules.append(module)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ('opt/parto-vm','etc/systemd/system','etc/parto'):(root/name).mkdir(parents=True,exist_ok=True)
            (root/'opt/parto-vm/build.json').write_text(json.dumps({'source_files':{},'architecture':'amd64'}))
            modules[0].stage(ROOT,root)
            pins=json.loads((root/'etc/parto/standalone-install.json').read_text())['helpers']
            self.assertEqual(set(pins),modules[1].IMMUTABLE_HELPERS)
            self.assertIn('standalone_workflow.py',pins)
