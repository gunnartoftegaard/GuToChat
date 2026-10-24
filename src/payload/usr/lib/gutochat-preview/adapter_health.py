"""A running HTTP/TCP API is insufficient to qualify a serial radio adapter."""

def healthy(reply,binding):
    if not isinstance(reply,dict) or reply.get('ok') is not True:return False
    status=reply.get('status')
    if not isinstance(status,dict) or status.get('online') is not True:return False
    if status.get('serial_port')!=binding['serial_port']:return False
    if status.get('route_key')!=binding['config_file'][5:-5]:return False
    if type(status.get('local_num')) is not int or status['local_num']<=0:return False
    health=status.get('receive_health')
    return isinstance(health,dict) and health.get('state') in ('RECENT_RECEPTION','NO_RECENT_DATA','NO_OBSERVATION')
