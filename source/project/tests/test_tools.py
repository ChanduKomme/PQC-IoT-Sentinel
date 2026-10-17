import copy,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from project_config import validate_registry,read_env,c_string
from evidence import parse_event,unique_events
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
FP=module('fingerprint','host-tools/provision_fingerprint.py')
FAULT=module('fault','hardware_security/fault_campaign_analyzer.py')
DTLS=module('dtls','experiments/dtls_baseline/tools/analyze_dtls_baseline.py')
GOV=module('governance','dashboard/backend/governance_service.py')
class ToolsTest(unittest.TestCase):
    def command(self,*args,expected=0):
        result=subprocess.run([sys.executable,*map(str,args)],capture_output=True,text=True,cwd=ROOT)
        self.assertEqual(result.returncode,expected,result.stdout+result.stderr);return result
    def test_lifecycle_and_headers(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            tmp=Path(temp);state=tmp/'registry.json';cli=ROOT/'pi2_trust_authority/trust_authority.py'
            self.command(cli,'--state',state,'init')
            for slot in (1,2):self.command(cli,'--state',state,'enroll','--slot',slot,'--sender-id',f'0x53454E3{slot}','--name',f'board-{slot}')
            self.command(cli,'--state',state,'enroll','--slot',1,'--sender-id','0x53454E31','--name','overwrite',expected=2)
            for role in ['sender','Receiver']:
                dest=tmp/role/role/'include';dest.mkdir(parents=True)
                (dest/'security_profile.h').write_text((ROOT/role/role/'include/security_profile.h').read_text())
            tool=ROOT/'tools/provision_device_identity.py'
            self.command(tool,'--project-root',tmp,'sender','--registry',state,'--slot',2)
            self.command(tool,'--project-root',tmp,'receiver','--registry',state)
            profile=tmp/'sender/sender/include/security_profile.h';before=profile.read_text()
            self.command(ROOT/'host-tools/provision_fingerprint.py','--out',profile,'--fingerprint-hex','ab'*32,'--gateway-ip','192.0.2.10')
            after=profile.read_text()
            for text in ['PQC_SENDER_ID 0x53454E32u','PQC_SECURITY_PROFILE_VERSION 4u','PQC_PROTOCOL_VERSION 3u','PQC_DEVICE_AUTH_TAG_LEN 32u','PQC-IOT-MLKEM512-AES256-CCM-v4']:self.assertIn(text,after)
            self.command(ROOT/'host-tools/provision_fingerprint.py','--out',profile,'--fingerprint-hex','ab'*32,'--gateway-ip','192.0.2.10','--sender-id','0x53454E31',expected=2)
            self.command(cli,'--state',state,'revoke','--slot',2)
            self.command(tool,'--project-root',tmp,'sender','--registry',state,'--slot',2,expected=2)
            old=json.loads(state.read_text())['devices'][1]['auth_key_hex']
            self.command(cli,'--state',state,'rotate','--slot',2)
            d=json.loads(state.read_text())['devices'][1];self.assertEqual(d['generation'],2);self.assertNotEqual(old,d['auth_key_hex'])
            if os.name=='posix':self.assertEqual(state.stat().st_mode&0o777,0o600)
    def test_registry_validation(self):
        base={'version':1,'devices':[{'slot':1,'sender_id':1,'name':'a','status':'active','generation':1,'auth_key_hex':'ab'*32}]}
        validate_registry(base)
        for key,value in [('slot',3),('sender_id',0),('generation',False),('auth_key_hex','00'*32),('status','unknown')]:
            d=copy.deepcopy(base);d['devices'][0][key]=value
            with self.assertRaises(ValueError):validate_registry(d)
        d=copy.deepcopy(base);d['devices']*=2
        with self.assertRaises(ValueError):validate_registry(d)
    def test_fingerprint_validation(self):
        self.assertEqual(FP.normalize_fingerprint(':'.join(['ab']*32)),'AB'*32)
        for bad in ['00'*32,'GG'+'ab'*31,'0x'+'ab'*32,'ab'*33]:
            with self.assertRaises(ValueError):FP.normalize_fingerprint(bad)
        self.command(ROOT/'host-tools/provision_fingerprint.py','--fingerprint-hex','ab'*32,'--gateway-ip','::1',expected=2)
    def test_env_is_data(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            p=Path(tmp)/'config';p.write_text('WIFI_PW="literal $(not_a_command) $stuff; and spaces"\n')
            self.assertIn('$(not_a_command)',read_env(p)['WIFI_PW'])
            p.write_text('WIFI_PW=x\nWIFI_PW=y\n')
            with self.assertRaises(ValueError):read_env(p)
        self.assertEqual(c_string('a"b\\c'),'"a\\"b\\\\c"')
    def test_event_provenance_and_dedup(self):
        event={'event_type':'MSG_DECRYPTED','origin':'firmware','role':'gateway','device_id':'g','experiment_id':'test','event_id':'capture:1'}
        self.assertEqual(parse_event('[EVENT] '+json.dumps(event)),event)
        self.assertIsNone(parse_event('host says MSG_DECRYPTED'))
        self.assertEqual(len(unique_events([event,event])),1)
        with self.assertRaises(ValueError):unique_events([{**event,'event_id':''}])
        with self.assertRaises(ValueError):unique_events([event,{**event,'event_type':'REPLAY_REJECT'}])
    def test_verifier_exact_counts(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            p=Path(tmp)/'events.jsonl';out=Path(tmp)/'verdict.json'
            d={'event_type':'MSG_DECRYPTED','origin':'firmware','role':'gateway','device_id':'g','experiment_id':'test','event_id':'c:1'}
            p.write_text(json.dumps(d)+'\n'+json.dumps(d)+'\n')
            cli=ROOT/'pi2_trust_authority/independent_verifier.py'
            self.command(cli,'--experiment-id','test','--event','MSG_DECRYPTED','--expected-min',1,'--expected-max',1,'--receiver-log',p,'--out',out)
            self.command(cli,'--experiment-id','test','--event','MSG_DECRYPTED','--expected-min',2,'--receiver-log',p,'--out',out,expected=1)
            self.command(cli,'--experiment-id','missing','--event','MSG_DECRYPTED','--receiver-log',p,'--out',out,expected=2)
    def test_fault_validation(self):
        row={'trial':'1','boot_ok':'1','auth_bypass':'0','secret_exposed':'0','reset_detected':'0'}
        self.assertEqual(FAULT.analyze([row])['security_result'],'NO_BYPASS_OBSERVED')
        self.assertEqual(FAULT.analyze([{**row,'auth_bypass':'1'}])['security_result'],'FAIL')
        for rows in [[],[row,row],[{**row,'auth_bypass':''}]]:
            with self.assertRaises(ValueError):FAULT.analyze(rows)
    def test_governance_file_resolves(self):
        self.assertTrue(GOV.risk_register_path().is_file());self.assertGreater(GOV.load_risks()['risk_count'],0)
        self.assertIn('DEVICE_AUTH_FAIL',GOV.ATTACK_EVENTS)
    def test_dtls_success_rtt_only(self):
        rows=[{'kind':'DTLS_BENCH','role':'sender','success':1,'rtt_ms':20},{'kind':'DTLS_BENCH','role':'sender','success':0,'rtt_ms':5000}]
        result=DTLS.build_summary(rows);self.assertEqual(result['sender_failed'],1);self.assertEqual(result['rtt_ms']['mean'],20)
    def test_tvla_input_and_shift(self):
        try:import numpy as np
        except ImportError:self.skipTest('optional NumPy not installed')
        tvla=module('tvla','hardware_security/tvla_screen.py');rng=np.random.default_rng(4)
        a=rng.normal(size=(200,8));b=rng.normal(size=(200,8))
        self.assertTrue(tvla.screen(a,b)[0]['screening_pass']);self.assertFalse(tvla.screen(a,b+4)[0]['screening_pass'])
        for x,y in [(a[:1],b),(a,b[:,:7]),(np.full((3,2),np.nan),np.ones((3,2))),(np.ones((3,2)),np.ones((3,2)))]:
            with self.assertRaises(ValueError):tvla.screen(x,y)
if __name__=='__main__':unittest.main()
