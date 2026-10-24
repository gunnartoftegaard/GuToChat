"""Exercise actual candidate GUI/core methods with synthetic boundaries only."""
import argparse,ast,functools,pathlib,queue,sys,types,unittest
from unittest.mock import Mock
BASE=None
@functools.lru_cache(None)
def code(role):
    module=types.ModuleType('review_map_mode_'+role);sys.modules[module.__name__]=module
    exec(compile((BASE/role/'map_mode_control.py').read_bytes(),'reviewed_map_mode','exec'),module.__dict__)
    calls=[]
    class Thread:
        def __init__(self,**kwargs):self.kwargs=kwargs
        def start(self):calls.append(self.kwargs)
    scope={**module.__dict__,'threading':types.SimpleNamespace(Thread=Thread),'tk':types.SimpleNamespace(TclError=RuntimeError),'queue':queue,'PRODUCT_NAME':'GuToChat','messagebox':types.SimpleNamespace(showinfo=Mock())}
    methods={}
    for file,clsname,names in [('lorad.py','RadioService',('start','enqueue_send','_wire_send')),('lorachat.py','LoRaChatApp',('_operator_select_online_map','_operator_select_offline_map','_on_notebook_tab_changed','_start_online_map_render','_online_map_render_worker','_close','send_selected'))]:
        tree=ast.parse((BASE/role/file).read_bytes());cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name==clsname)
        for n in cls.body:
            if isinstance(n,ast.FunctionDef) and n.name in names:
                program=ast.Module(body=[ast.ImportFrom(module='__future__',names=[ast.alias(name='annotations')],level=0),n],type_ignores=[])
                exec(compile(ast.fix_missing_locations(program),str(BASE/role/file),'exec'),scope);methods[clsname+'.'+n.name]=scope[n.name]
    return methods,scope,calls
def gui():
    return types.SimpleNamespace(_t=lambda key,**kw:key,online_map_status_var=types.SimpleNamespace(set=Mock()),offline_map_status_var=types.SimpleNamespace(set=Mock()),notebook=types.SimpleNamespace(select=Mock()),_refresh_map_mode_controls=Mock(),online_map_tab='online',map_tab='offline',messages_tab='messages')
class PreviewBoundaries(unittest.TestCase):
    def test_core_only_does_not_start_private_radio(self):
        for role in ('BASE','FIELD'):
            with self.subTest(role=role):
                methods,scope,calls=code(role);calls.clear();obj=types.SimpleNamespace(private_radio_enabled=False,_radio_loop=Mock(),_maintenance_loop=Mock())
                methods['RadioService.start'](obj)
                self.assertEqual([x['name'] for x in calls],['database-maintenance'])
    def test_disabled_private_radio_refuses_before_store_or_wire_access(self):
        for role in ('BASE','FIELD'):
            with self.subTest(role=role):
                methods,_,_=code(role);obj=types.SimpleNamespace(private_radio_enabled=False)
                with self.assertRaisesRegex(RuntimeError,'PRIVATE_RADIO_NOT_CONFIGURED'):methods['RadioService.enqueue_send'](obj,2,'synthetic')
                with self.assertRaisesRegex(RuntimeError,'PRIVATE_RADIO_NOT_CONFIGURED'):methods['RadioService._wire_send'](obj,2,b'synthetic')
    def test_selecting_online_changes_mode_without_starting_fetch(self):
        for role in ('BASE','FIELD'):
            with self.subTest(role=role):
                methods,scope,calls=code(role);calls.clear();obj=gui();methods['LoRaChatApp._operator_select_online_map'](obj)
                self.assertIs(obj.map_operator_mode,scope['MapOperatorMode'].ONLINE);self.assertEqual(calls,[])
    def test_tab_selection_requests_local_refresh_not_tile_fetch(self):
        for role in ('BASE','FIELD'):
            with self.subTest(role=role):
                methods,scope,calls=code(role);calls.clear();obj=gui();obj._active_tab_is=lambda tab:tab=='online'
                obj._refresh_online_map_rows=Mock();obj._start_message_history_refresh=Mock();obj._start_map_refresh=Mock();obj._schedule_refresh=Mock()
                methods['LoRaChatApp._on_notebook_tab_changed'](obj)
                obj._refresh_online_map_rows.assert_called_once();obj._start_message_history_refresh.assert_not_called();obj._start_map_refresh.assert_not_called();self.assertEqual(calls,[])
    def test_tile_fetch_requires_online_and_allows_one_worker(self):
        for role in ('BASE','FIELD'):
            with self.subTest(role=role):
                methods,scope,calls=code(role);calls.clear();obj=gui();obj.map_operator_mode=scope['MapOperatorMode'].OFFLINE
                obj._online_viewport=Mock(return_value='synthetic');methods['LoRaChatApp._start_online_map_render'](obj);obj._online_viewport.assert_not_called();self.assertEqual(calls,[])
                obj.map_operator_mode=scope['MapOperatorMode'].ONLINE;obj.online_map_render_running=False;obj.online_map_render_generation=0;obj.online_map_load_button=types.SimpleNamespace(configure=Mock());obj._online_map_render_worker=Mock()
                methods['LoRaChatApp._start_online_map_render'](obj);methods['LoRaChatApp._start_online_map_render'](obj)
                self.assertEqual(len(calls),1);self.assertTrue(obj.online_map_render_running)
    def test_offline_selection_invalidates_online_results(self):
        for role in ('BASE','FIELD'):
            with self.subTest(role=role):
                methods,scope,calls=code(role);calls.clear();obj=gui();obj.map_operator_mode=scope['MapOperatorMode'].ONLINE;obj.online_map_render_generation=5
                methods['LoRaChatApp._operator_select_offline_map'](obj,fallback_error='synthetic error')
                self.assertIs(obj.map_operator_mode,scope['MapOperatorMode'].OFFLINE);self.assertEqual(obj.online_map_render_generation,6);self.assertEqual(calls,[])
    def test_no_selected_network_does_not_read_or_send_message(self):
        for role in ('BASE','FIELD'):
            with self.subTest(role=role):
                methods,_,_=code(role);obj=gui();obj.network_order=[]
                methods['LoRaChatApp.send_selected'](obj) # No message widget, client or radio exists.
    def test_close_cancels_registered_ui_callbacks(self):
        for role in ('BASE','FIELD'):
            with self.subTest(role=role):
                methods,_,_=code(role);obj=types.SimpleNamespace(after_cancel=Mock(),destroy=Mock(),aprs_live_runtime=None)
                fields=('_maintenance_after_id','message_refresh_poll_after_id','map_refresh_poll_after_id','online_map_render_poll_after_id','offline_map_redraw_after_id','refresh_after_id')
                for i,name in enumerate(fields):setattr(obj,name,'synthetic-'+str(i))
                methods['LoRaChatApp._close'](obj)
                self.assertTrue(obj._gui_closing);self.assertEqual(obj.after_cancel.call_count,len(fields));obj.destroy.assert_called_once()
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('base',type=pathlib.Path);a=p.parse_args();BASE=a.base
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(PreviewBoundaries));assert result.wasSuccessful()
