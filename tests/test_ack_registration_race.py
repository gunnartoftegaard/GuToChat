"""Exercise actual send_text source with deterministic callback interleavings; no SDK/radio."""
import argparse, ast, json, pathlib, threading, types, uuid

def method(path):
    tree = ast.parse(path.read_bytes())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'MeshBridge')
    fn = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'send_text')
    scope = dict(Any=object, threading=threading, uuid=uuid,
                 destination_to_num=lambda value: 0xffffffff if value == '^all' else 42,
                 BROADCAST_NUM=0xffffffff, transport_failure=lambda interface: False,
                 now_iso=lambda: 'synthetic-time', time=types.SimpleNamespace(time=lambda: 100),
                 LOG=types.SimpleNamespace(info=lambda *a: None))
    exec(compile(ast.Module(body=[fn], type_ignores=[]), str(path), 'exec'), scope)
    return scope['send_text']

def exercise(send, timing, direct=True):
    received=[]; pending={}; texts=[]; calls=[]; hook={}
    def ack(): hook['callback']({'decoded': {'routing': {'errorReason': 'NONE'}}})
    class Interface:
        def sendText(self, text, **kwargs):
            calls.append(kwargs); hook['callback']=kwargs['onResponse']
            if direct and timing == 'inside_send': ack()
            return types.SimpleNamespace(id=123)
    class Store:
        def add_meshtastic(self, **kwargs):
            texts.append(kwargs)
            if direct and timing == 'before_pending': ack()
        def add_pending(self, **kwargs):
            if timing == 'during_pending': ack()
            pending[kwargs['packet_id']]=kwargs
    def response(context, packet):
        item=pending.pop(context['packet_id'],None)
        if item: received.append(item['message_uid'])
    bridge=types.SimpleNamespace(online=True,interface=Interface(),channel_index=0,
        send_lock=threading.Lock(),store=Store(),local_num=1,local_name='synthetic',
        uid_prefix='synthetic',route_key='mesh_test',network_name='Test radio',
        mesh_ack_timeout=30,_node_label=lambda n:'synthetic',_handle_mesh_response=response)
    result=send(bridge,'synthetic message', '!0000002a' if direct else '^all')
    if direct and timing == 'after_return': ack()
    assert result=='123'
    assert len(texts)==1 and len(calls)==1
    assert calls[0]['wantAck'] is direct
    if direct: assert received==['synthetic-123'] and not pending, (timing, received, pending)
    else: assert not pending and not received and calls[0]['onResponse'] is None

def run(base):
    results=[]
    for role in ('BASE','FIELD'):
        send=method(base/role/'meshbridge.py')
        for timing in ('inside_send','before_pending','during_pending','after_return'):
            try: exercise(send,timing)
            except AssertionError: state='FAIL'
            else: state='PASS'
            results.append(dict(role=role,timing=timing,state=state))
        exercise(send,'broadcast',False)
        results.append(dict(role=role,timing='broadcast',state='PASS'))
    return results

if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('base',type=pathlib.Path); p.add_argument('--expect-failure',action='store_true'); a=p.parse_args()
    results=run(a.base); print(json.dumps(results,indent=2))
    failed=[r for r in results if r['state']=='FAIL']
    if a.expect_failure:
        assert {(r['role'],r['timing']) for r in failed}=={(role,t) for role in ('BASE','FIELD') for t in ('before_pending','during_pending')}
    else: assert not failed
