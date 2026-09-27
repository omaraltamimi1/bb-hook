import argparse,json,os,signal,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from autorecon_v8.core import Scope,atomic_json,normalize_target,normalize_url,origin,select_stages,unique_origins

class Unit(unittest.TestCase):
 def test_malformed(self):
  for x in ('','999.1.1.1','ftp://x.test','https://u:p@x.test','localhost'):
   with self.assertRaises(ValueError):normalize_target(x)
 def test_normalization(self):
  self.assertEqual(normalize_url('HTTPS://Example.COM:443/a#x'),'https://example.com/a')
  self.assertEqual(origin('http://Example.com:80/a'),'http://example.com')
 def test_duplicate_origins(self):self.assertEqual(unique_origins(['https://EXAMPLE.com/a','https://example.com/b','http://example.com']),['https://example.com','http://example.com'])
 def test_scope_wildcard_exclusion(self):
  s=Scope('example.com',['example.com'],['bad.example.com']); self.assertTrue(s.decide('https://a.example.com')[0]); self.assertFalse(s.decide('https://x.bad.example.com')[0]); self.assertFalse(s.decide('https://evil.test')[0])
 def test_redirect_scope(self):self.assertFalse(Scope('example.com').decide('https://evil.test/redirected')[0])
 def test_atomic_checkpoint(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'x.json'; atomic_json(p,{'x':1}); self.assertEqual(json.loads(p.read_text()),{'x':1})
 def ns(self,**kw):
  d=dict(only=None,skip=None,profile='custom',from_stage=None,until=None,restart_stage=None,passive=False);d.update(kw);return argparse.Namespace(**d)
 def test_selection(self):
  s,r=select_stages(self.ns(only=['dns,httpx']));self.assertEqual(s,{'dns','httpx','report'});self.assertIn('not selected',r['tls'])
  s,_=select_stages(self.ns(from_stage='crawl',until='corpus'));self.assertEqual(s,{'crawl','archives','corpus'})
  s,r=select_stages(self.ns(skip=['nmap']));self.assertNotIn('nmap',s);self.assertIn('retired',r['nmap']);self.assertIn('ports',r['nmap']);self.assertRaises(ValueError,select_stages,self.ns(skip=['definitely-not-a-stage']))

class Integration(unittest.TestCase):
 def run_cli(self,*args,timeout=10,env=None):return subprocess.run([sys.executable,'-m','autorecon_v8',*args],text=True,capture_output=True,timeout=timeout,env=env)
 def test_dry_empty_missing_and_report(self):
  with tempfile.TemporaryDirectory() as d:
   r=self.run_cli('example.com','--dry-run','--only','dns,api-discovery','--output-dir',d);self.assertEqual(r.returncode,0,r.stderr)
   run=next(p for p in Path(d).iterdir() if p.is_dir()); report=json.loads((run/'report.json').read_text());self.assertTrue((run/'report.md').exists());self.assertTrue((run/'stages.csv').exists());self.assertEqual(report['stages'][0]['status'],'completed')
 def test_resume_no_duplicates(self):
  with tempfile.TemporaryDirectory() as d:
   self.assertEqual(self.run_cli('example.com','--dry-run','--only','dns','--output-dir',d).returncode,0); rid=(Path(d)/'last').read_text(); self.assertEqual(self.run_cli('example.com','--dry-run','--only','dns','--resume',rid,'--output-dir',d).returncode,0); lines=(Path(d)/rid/'raw-artifacts/dns/normalized.txt').read_text().splitlines();self.assertEqual(lines,['example.com'])
 def test_subdomains_flow_to_dnsx_httpx_and_ports(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'bin';b.mkdir()
   scripts={
    'subfinder':'#!/bin/sh\nprintf "api.example.com\\nwww.example.com\\n"\n',
    'dnsx':'#!/bin/sh\ncat "$(printf "%s\\n" "$@" | tail -1)"\n',
    'httpx':'#!/bin/sh\nwhile read h; do printf "https://%s/\\n" "$h"; done < "$(printf "%s\\n" "$@" | tail -1)"\n',
    'naabu':'#!/bin/sh\nwhile read h; do printf "%s:443\\n" "$h"; done < "$(printf "%s\\n" "$@" | tail -1)"\n',
   }
   for name,body in scripts.items(): p=b/name;p.write_text(body);p.chmod(0o755)
   env=os.environ.copy();env['PATH']=str(b)+os.pathsep+env['PATH']
   r=self.run_cli('example.com','--only','subdomains,dnsx,httpx,ports','--output-dir',d,env=env);self.assertEqual(r.returncode,0,r.stderr)
   rid=(Path(d)/'last').read_text();raw=Path(d)/rid/'raw-artifacts'
   expected={'api.example.com','www.example.com','example.com'}
   self.assertEqual(set((raw/'dnsx/normalized.txt').read_text().splitlines()),expected)
   self.assertEqual(set((raw/'httpx/normalized.txt').read_text().splitlines()),{f'https://{h}/' for h in expected})
   self.assertEqual(set((raw/'ports/normalized.txt').read_text().splitlines()),{f'{h}:443' for h in expected})
 def test_stage_global_timeout_partial(self):
  with tempfile.TemporaryDirectory() as d:
   r=self.run_cli('example.com','--only','api-discovery','--request-timeout','.1','--stage-timeout','.001','--global-timeout','.001','--output-dir',d);self.assertNotEqual(r.returncode,0);run=next(p for p in Path(d).iterdir() if p.is_dir());self.assertTrue((run/'report.json').exists())
 def test_hanging_child_interrupt(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d)/'bin';b.mkdir();x=b/'dig';x.write_text('#!/bin/sh\nsleep 30\n');x.chmod(0o755);env=os.environ.copy();env['PATH']=str(b)+os.pathsep+env['PATH'];p=subprocess.Popen([sys.executable,'-m','autorecon_v8','example.com','--only','dns','--output-dir',d,'--tool-timeout','30'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);time.sleep(.5);p.send_signal(signal.SIGINT);p.communicate(timeout=5);self.assertEqual(p.returncode,130);rid=(Path(d)/'last').read_text();self.assertTrue((Path(d)/rid/'report.json').exists())
 def test_worker_body_isolation(self):
  import http.server,threading
  srv=http.server.ThreadingHTTPServer(('127.0.0.1',0),http.server.SimpleHTTPRequestHandler);t=threading.Thread(target=srv.serve_forever,daemon=True);t.start()
  try:
   with tempfile.TemporaryDirectory() as d:
    target=f'http://127.0.0.1:{srv.server_port}';r=self.run_cli(target,'--only','api-discovery','--output-dir',d,'--request-timeout','1');self.assertEqual(r.returncode,0,r.stderr);rid=(Path(d)/'last').read_text();bodies=list((Path(d)/rid/'raw-artifacts/api-discovery').glob('*.body'));self.assertEqual(len(bodies),7);self.assertEqual(len({x.name for x in bodies}),7)
  finally:srv.shutdown()
 def test_large_corpus_dedupe(self):self.assertEqual(len(unique_origins(f'https://example.com/{i}' for i in range(10000))),1)

def load_tests(loader,tests,pattern):
 # unittest.main() only scans this module's namespace, so a plain import of a sibling test
 # module is not enough to register its cases. load_tests is the supported way to extend the suite.
 import tests.stage_coverage as stage_coverage
 import tests.access_matrix as access_matrix
 tests.addTests(loader.loadTestsFromModule(stage_coverage))
 tests.addTests(loader.loadTestsFromModule(access_matrix))
 return tests

if __name__=='__main__':unittest.main(verbosity=2)
