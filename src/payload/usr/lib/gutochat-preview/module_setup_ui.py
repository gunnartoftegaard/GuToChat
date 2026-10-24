"""Bilingual optional radio registration; fixed argv, local authentication."""
import os,pathlib,queue,subprocess,sys,threading
sys.dont_write_bytecode=True
if os.name!='posix' or os.geteuid()==0:raise SystemExit('USE_ORDINARY_DESKTOP_ACCOUNT')
CODE=pathlib.Path('/usr/lib/gutochat-preview');sys.path.insert(0,str(CODE))
from usb_inventory import inventory
from adapter_manifest import validate_device
import tkinter as tk
from tkinter import ttk,messagebox

TEXT={
 'nb':{'title':'Installer radiomodul','help':'Koble til én ledig Meshtastic-radio med riktig antenne. Lukk GuToChat Base og Field før registrering. Radioen registreres avslått; velg og aktiver den senere i Oppsett og enheter. Frekvensoppsett endres ikke.','scan':'Finn USB-radioer','usb':'USB-enhet','role':'Oppsett','band':'Radioens frekvensbånd','route':'Rute-ID','label':'Navn','port':'Lokal API-port','channel':'Kanalindeks','apply':'Registrer radio','confirm':'Registrere denne radioen avslått for {role}?','done':'Radioen er registrert, men ikke aktivert. Åpne GuToChat og velg radioen i Oppsett og enheter.','failed':'Registreringen er ikke fullført. Årsak: {reason}','busy':'Venter på administratorbekreftelse og kontroll …','empty':'Ingen USB-radioer med unik identitet funnet.','close':'Lukk'},
 'en':{'title':'Install radio module','help':'Connect one spare Meshtastic radio with a suitable antenna. Close GuToChat Base and Field before registration. The radio is registered disabled; select and activate it later in Setup and devices. Radio settings are not changed.','scan':'Find USB radios','usb':'USB device','role':'Setup','band':'Radio frequency band','route':'Route ID','label':'Name','port':'Local API port','channel':'Channel index','apply':'Register radio','confirm':'Register this radio disabled for {role}?','done':'The radio is registered, but not activated. Open GuToChat and select it in Setup and devices.','failed':'Registration is not complete. Reason: {reason}','busy':'Waiting for administrator confirmation and checks …','empty':'No USB radios with a unique identity found.','close':'Close'}}

class Wizard(tk.Tk):
    def __init__(self):
        super().__init__();self.lang='en' if '--english' in sys.argv else 'nb';self.words=TEXT[self.lang]
        self.title(self.words['title']);self.active=False;self.result=queue.Queue();self.usb={}
        self.protocol('WM_DELETE_WINDOW',self.close)
        frame=ttk.Frame(self,padding=18);frame.pack(fill='both',expand=True)
        ttk.Label(frame,text=self.words['help'],wraplength=650).grid(row=0,column=0,columnspan=2,sticky='w',pady=10)
        self.values={};self.controls=[]
        for row,(name,default,choices) in enumerate([('role','base',('base','field')),('usb','',()),('band','',('433','868')),('route','mesh_test',None),('label','Test radio',None),('port','23001',None),('channel','0',None)],1):
            value=tk.StringVar(self,value=default);self.values[name]=value
            ttk.Label(frame,text=self.words[name]).grid(row=row,column=0,sticky='w',padx=(0,12),pady=4)
            control=ttk.Combobox(frame,textvariable=value,values=choices,state='readonly') if choices is not None else ttk.Entry(frame,textvariable=value)
            control.grid(row=row,column=1,sticky='ew');self.controls.append(control)
            if name=='usb':self.usb_box=control
        buttons=ttk.Frame(frame);buttons.grid(row=8,column=0,columnspan=2,pady=12)
        for label,action in [('scan',self.scan),('apply',self.apply),('close',self.close)]:
            button=ttk.Button(buttons,text=self.words[label],command=action);button.pack(side='left',padx=4);self.controls.append(button)
        self.status=tk.StringVar(self);ttk.Label(frame,textvariable=self.status,wraplength=650).grid(row=9,column=0,columnspan=2,sticky='w')
        self.scan()
    def close(self):
        if not self.active:self.destroy()
    def scan(self):
        try:
            found=inventory();self.usb={pathlib.PurePosixPath(v['stable_path']).name:k for k,v in found.items()}
            self.usb_box.configure(values=tuple(self.usb));self.values['usb'].set(next(iter(self.usb),''))
            self.status.set('' if found else self.words['empty'])
        except Exception:self.status.set(self.words['failed'].format(reason='USB_OBSERVATION_FAILED'))
    def apply(self):
        if self.active:return
        try:
            v={k:x.get().strip() for k,x in self.values.items()};usb=self.usb[v['usb']]
            validate_device({'kind':'meshtastic_usb','route_key':v['route'],'label':v['label'],'band':v['band'],'usb_id':usb,'api_port':int(v['port']),'channel_index':int(v['channel'])})
        except (ValueError,KeyError):messagebox.showerror(self.words['title'],self.words['failed'].format(reason='INVALID_SELECTION'),parent=self);return
        if not messagebox.askokcancel(self.words['title'],self.words['confirm'].format(role=v['role'].capitalize()),parent=self):return
        argv=['/usr/bin/pkexec','/usr/bin/python3','-I',str(CODE/'admin.py'),'register-radio',v['role'],usb,v['route'],v['label'],v['band'],v['port'],v['channel']]
        try:p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        except OSError:self.status.set(self.words['failed'].format(reason='AUTHENTICATION_UNAVAILABLE'));return
        self.active=True;self.status.set(self.words['busy'])
        for control in self.controls:control.configure(state='disabled')
        def collect():
            raw,_=p.communicate();self.result.put((p.returncode,raw))
        threading.Thread(target=collect,daemon=True).start()
        def poll():
            try:code,raw=self.result.get_nowait()
            except queue.Empty:self.after(150,poll);return
            import json
            try:record=json.loads(raw)
            except ValueError:record={}
            self.active=False
            for control in self.controls:control.configure(state='normal')
            for control in self.controls[:3]:control.configure(state='readonly')
            ok=code==0 and record.get('state')=='COMPLETE_DISABLED'
            self.status.set(self.words['done'] if ok else self.words['failed'].format(reason=record.get('reason',record.get('state','AUTHENTICATION_FAILED_OR_CANCELLED'))))
        self.after(150,poll)

if __name__=='__main__':Wizard().mainloop()
