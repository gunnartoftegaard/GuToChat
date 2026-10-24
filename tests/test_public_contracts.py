"""Adapted public installer contracts. Uses pure functions or mocked host effects."""
import pathlib,sys,os,json,copy,tempfile,types,unittest
from unittest.mock import patch
CODE=pathlib.Path(os.environ.get('GUTOCHAT_CANDIDATE_CODE',pathlib.Path(__file__).parent/'candidate_payload/usr/lib/gutochat-preview'))
sys.path.insert(0,str(CODE));import layout,setup_model,adapter_manifest,admin

class PublicContracts(unittest.TestCase):
 def setUp(self):
  paths=patch.multiple(layout,CONFIG=pathlib.PurePosixPath('/etc/gutochat-preview'),STATE=pathlib.PurePosixPath('/var/lib/gutochat-preview'))
  paths.start();self.addCleanup(paths.stop)
  self.selection=layout.selection('base','nb','tester','tester',1000,1000)
  self.core=layout.configuration(self.selection,23000);self.registry=layout.registry(self.selection)
  self.registration={'schema_version':1,'selection':self.selection,'units':{}}
  self.device={'kind':'meshtastic_usb','route_key':'mesh_test','label':'Test radio','band':'433','usb_id':'usb1','api_port':23001,'channel_index':0}
  self.inventory={'usb1':{'stable_path':'/dev/serial/by-id/usb-Synthetic_1','device_number':188001,'identity_sha256':'a'*64}}
 def recipe(self,inventory=None,device=None):
  return adapter_manifest.make_recipe(self.core,self.registration,self.registry,[self.device if device is None else device],self.inventory if inventory is None else inventory,True)
 def test_role_and_language_isolation(self):
  field=layout.configuration(layout.selection('field','en','tester','tester',1000,1000),23002)
  self.assertNotEqual(field['database'],self.core['database']);self.assertEqual(field['ui_language'],'en');self.assertEqual(self.core['ui_language'],'nb')
 def test_core_only_has_no_implicit_radio_or_publication(self):
  self.assertFalse(self.core['private_radio_enabled']);self.assertEqual(self.core['meshtastic_radios'],[])
  self.assertFalse(self.core['map_aprs_live_enabled']);self.assertFalse(self.core['map_aprs_headless_enabled'])
 def test_privileged_command_is_fixed_argv_without_shell(self):
  args=setup_model.command('install','base','nb','tester')
  self.assertEqual(args,['/usr/bin/pkexec','/usr/bin/python3','-I','/usr/lib/gutochat-preview/admin.py','setup','base','nb','tester'])
 def test_invalid_role_language_action_and_account_rejected(self):
  for args in [('install','../base','nb','tester'),('install','base','de','tester'),('shell','base','nb','tester'),('install','base','nb','tester;touch x')]:
   with self.subTest(args=args),self.assertRaises(ValueError):setup_model.command(*args)
 def test_cancelled_auth_never_reports_success_even_with_success_payload(self):
  for lang in ('nb','en'):
   ok,text=setup_model.outcome(126,'{"state":"INSTALLED"}',lang);self.assertFalse(ok);self.assertEqual(text,setup_model.TEXT[lang]['cancelled'])
 def test_auth_failure_never_reports_success(self):
  ok,text=setup_model.outcome(127,'{"state":"INSTALLED"}','en');self.assertFalse(ok);self.assertEqual(text,setup_model.TEXT['en']['auth'])
 def test_malformed_backend_result_rejected(self):
  self.assertFalse(setup_model.outcome(0,'not json','en')[0]);self.assertFalse(setup_model.outcome(0,'[]','en')[0])
 def test_backend_failure_cannot_be_masked_by_success_state(self):
  self.assertFalse(setup_model.outcome(1,'{"state":"INSTALLED"}','en')[0])
 def test_error_text_cannot_echo_arbitrary_backend_content(self):
  ok,text=setup_model.outcome(1,json.dumps({'reason':'private text with /home/operator/token'}),'en')
  self.assertFalse(ok);self.assertNotIn('private text',text);self.assertIn('OPERATION_FAILED',text)
 def test_existing_setup_guides_to_resume(self):
  ok,text=setup_model.outcome(1,'{"reason":"EXISTING_INSTALLATION_REVIEW_REQUIRED"}','nb')
  self.assertFalse(ok);self.assertEqual(text,setup_model.TEXT['nb']['existing'])
 def test_unrecognized_zero_exit_result_is_not_success(self):
  self.assertFalse(setup_model.outcome(0,'{"state":"UNKNOWN"}','en')[0])
 def test_missing_usb_refuses_recipe_without_input_mutation(self):
  before=copy.deepcopy((self.core,self.registry,self.registration,self.device))
  with self.assertRaisesRegex(adapter_manifest.CommissionError,'USB_NOT_OBSERVED'):self.recipe(inventory={})
  self.assertEqual(before,(self.core,self.registry,self.registration,self.device))
 def test_route_port_collision_is_refused(self):
  with self.assertRaisesRegex(adapter_manifest.CommissionError,'DUPLICATE_ROUTE_OR_PORT'):self.recipe(device=dict(self.device,api_port=self.core['api_port']))
 def test_usb_identity_change_refuses_old_recipe(self):
  recipe=self.recipe();observed=copy.deepcopy(self.inventory);observed['usb1']['identity_sha256']='b'*64
  with self.assertRaisesRegex(adapter_manifest.CommissionError,'USB_CHANGED'):
   adapter_manifest.revalidate(recipe,self.core,self.registration,self.registry,observed,True)
 def test_planning_retains_inputs_and_does_not_activate(self):
  before=copy.deepcopy((self.core,self.registry,self.registration,self.inventory));recipe=self.recipe()
  self.assertEqual(before,(self.core,self.registry,self.registration,self.inventory));self.assertEqual(recipe['activation'],'SEPARATE_EXPLICIT_STEP')
 def test_admin_without_privilege_refuses_before_host_operations(self):
  with patch.object(os,'geteuid',return_value=1000,create=True),patch.object(admin,'protected') as protected,patch.object(admin,'systemctl') as systemctl:
   with self.assertRaisesRegex(RuntimeError,'ADMINISTRATOR_REQUIRED'):admin.main()
   protected.assert_not_called();systemctl.assert_not_called()
 def test_existing_data_is_not_overwritten_by_new_setup(self):
  # Private synthetic workspace only. No live files, systemctl, or account changes.
  with tempfile.TemporaryDirectory(dir=pathlib.Path(__file__).parent) as tmp:
   root=pathlib.Path(tmp);config=root/'config';state=root/'state';existing=state/'data/base';existing.mkdir(parents=True)
   marker=existing/'sentinel';marker.write_bytes(b'preserve')
   fakepwd=types.SimpleNamespace(getpwnam=lambda _:types.SimpleNamespace(pw_name='tester',pw_uid=1000,pw_gid=1000))
   fakegrp=types.SimpleNamespace(getgrgid=lambda _:types.SimpleNamespace(gr_name='tester'))
   deps=types.SimpleNamespace(check=lambda:{'ready':True})
   with patch.multiple(layout,CONFIG=config,STATE=state,CODE=root),patch.object(layout,'os_supported',return_value=True),patch.object(admin,'protected'),patch.object(admin,'systemctl') as systemctl,patch.dict(sys.modules,{'pwd':fakepwd,'grp':fakegrp,'dependency_probe':deps}):
    with self.assertRaisesRegex(RuntimeError,'EXISTING_INSTALLATION_REVIEW_REQUIRED'):admin.setup('base','nb','tester',layout)
    systemctl.assert_not_called();self.assertEqual(marker.read_bytes(),b'preserve');self.assertFalse(config.exists())
 def test_existing_publication_is_not_silently_disabled(self):
  self.core['map_aprs_live_enabled']=True;before=copy.deepcopy(self.core)
  with self.assertRaisesRegex(adapter_manifest.CommissionError,'PUBLICATION_CHANGE_REQUIRES_REVIEW'):self.recipe()
  self.assertEqual(self.core,before)

if __name__=='__main__':unittest.main(verbosity=2)
