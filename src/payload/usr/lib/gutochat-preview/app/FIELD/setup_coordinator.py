"""In-process GUI preflight and one-use handoff to a trusted installer worker."""
import copy,threading,time,uuid
from activation import ActivationError

class SetupCoordinator:
    def __init__(self,engine,handoff,*,clock=time.monotonic,lifetime=300):
        self.engine=engine;self.handoff_worker=handoff;self.clock=clock;self.lifetime=lifetime
        self.pending={};self.lock=threading.Lock()

    def prepare(self,plan):
        # Never publish candidate config bytes, paths or credentials to the GUI.
        plan=copy.deepcopy(plan)
        with self.lock:self.pending.clear()
        prepared=self.engine.prepare(plan)
        if prepared['state']=='NO_CHANGE':return {'state':'NO_CHANGE','changes':[]}
        token=uuid.uuid4().hex
        with self.lock:
            self.pending.clear()
            self.pending[token]=(self.clock(),plan,prepared)
        return {'state':'READY','token':token,'changes':copy.deepcopy(plan['changes'])}

    def invalidate(self):
        with self.lock:self.pending.clear()

    def handoff(self,token):
        with self.lock:
            record=self.pending.pop(token,None)
        if record is None:raise ActivationError('SETUP_CHECK_REQUIRED')
        when,plan,prepared=record
        if self.clock()-when>self.lifetime:raise ActivationError('SETUP_CHECK_EXPIRED')
        self.engine.fresh(prepared)
        # The installer worker must independently prepare after the GUI process exits.
        receipt=self.handoff_worker(copy.deepcopy(plan))
        if not isinstance(receipt,dict) or receipt.get('state')!='WAITING_FOR_GUI_EXIT' or not isinstance(receipt.get('job_id'),str) or not receipt['job_id']:
            raise ActivationError('INSTALLER_HANDOFF_NOT_CONFIRMED')
        return {'state':'WAITING_FOR_GUI_EXIT','job_id':receipt['job_id']}
