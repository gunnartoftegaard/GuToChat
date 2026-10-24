"""Installer worker gate: actual application process must exit before mutation."""
import copy,os,time
from activation import ActivationError,owner_alive

def run_after_gui_exit(engine_factory,plan,parent_pid,*,timeout=60,alive=owner_alive,clock=time.monotonic,wait=time.sleep):
    if type(parent_pid) is not int or parent_pid<=0 or parent_pid==os.getpid():raise ActivationError('GUI_PROCESS_ID_INVALID')
    if not 1<=timeout<=300:raise ActivationError('GUI_EXIT_TIMEOUT_INVALID')
    start=clock()
    while alive(parent_pid):
        if clock()-start>=timeout:raise ActivationError('GUI_PROCESS_STILL_RUNNING')
        wait(.1)
    # Fresh configuration/profile/helper validation occurs after all GUI writers exit.
    engine=engine_factory()
    prepared=engine.prepare(copy.deepcopy(plan))
    return engine.apply(prepared)
