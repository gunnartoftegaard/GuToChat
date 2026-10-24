"""Bilingual installed wizard: fixed argv, responsive authentication, no data deletion."""
import os,pathlib,pwd,queue,subprocess,sys,threading
sys.dont_write_bytecode=True
CODE=pathlib.Path('/usr/lib/gutochat-preview')
if os.geteuid()==0:raise SystemExit('USE_ORDINARY_DESKTOP_ACCOUNT')
sys.path.insert(0,str(CODE))
from setup_model import TEXT,command,outcome
import tkinter as tk
from tkinter import ttk,messagebox

class Wizard(tk.Tk):
    def __init__(self):
        super().__init__()
        self.language=tk.StringVar(self,value='nb');self.role=tk.StringVar(self,value='base')
        self.active=False;self.results=queue.Queue();self.controls=[]
        self.frame=ttk.Frame(self,padding=22);self.frame.pack(fill='both',expand=True)
        self.protocol('WM_DELETE_WINDOW',self.close);self.resizable(False,False);self.render()
    def render(self):
        for child in self.frame.winfo_children():child.destroy()
        self.controls=[];words=TEXT[self.language.get()];self.title(words['title'])
        ttk.Label(self.frame,text=words['title'],font=('Arial',16,'bold')).pack(anchor='w',pady=(0,16))
        bar=ttk.Frame(self.frame);bar.pack(fill='x')
        ttk.Label(bar,text=words['language']).pack(side='left')
        for label,value in [('Norsk','nb'),('English','en')]:
            control=ttk.Radiobutton(bar,text=label,value=value,variable=self.language,command=self.render)
            control.pack(side='left',padx=12);self.controls.append(control)
        ttk.Label(self.frame,text=words['role']).pack(anchor='w',pady=(16,0))
        for role in ('base','field'):
            control=ttk.Radiobutton(self.frame,text=role.capitalize(),value=role,variable=self.role)
            control.pack(anchor='w');self.controls.append(control)
        for key in ('scope','help'):
            ttk.Label(self.frame,text=words[key],wraplength=640).pack(anchor='w',pady=(16,0))
        bar=ttk.Frame(self.frame);bar.pack(fill='x',pady=(20,14))
        for action in ('install','resume','deactivate'):
            control=ttk.Button(bar,text=words[action],command=lambda a=action:self.run_action(a))
            control.pack(side='left',padx=(0,8));self.controls.append(control)
        self.status=tk.StringVar(self,value=words['idle'])
        ttk.Label(self.frame,textvariable=self.status,wraplength=640).pack(anchor='w')
        control=ttk.Button(self.frame,text=words['close'],command=self.close)
        control.pack(anchor='e',pady=(14,0));self.controls.append(control)
    def close(self):
        if not self.active:self.destroy()
    def run_action(self,action):
        if self.active:return
        language=self.language.get();role=self.role.get();words=TEXT[language]
        if not messagebox.askokcancel(words['title'],words['confirm'].format(action=words[action],role=role.capitalize()),parent=self):return
        args=command(action,role,language,pwd.getpwuid(os.getuid()).pw_name)
        try:process=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        except OSError:
            messagebox.showerror(words['title'],words['auth'],parent=self);return
        self.active=True
        for control in self.controls:control.configure(state='disabled')
        self.status.set(words['busy'])
        def collect():
            try:
                stdout,_=process.communicate();self.results.put((process.returncode,stdout))
            except Exception:self.results.put((1,''))
        threading.Thread(target=collect,daemon=True).start()
        def poll():
            try:code,stdout=self.results.get_nowait()
            except queue.Empty:self.after(150,poll);return
            self.active=False
            for control in self.controls:control.configure(state='normal')
            success,explanation=outcome(code,stdout,language);self.status.set(explanation)
            show=messagebox.showinfo if success else messagebox.showerror
            show(words['title'],explanation,parent=self)
        self.after(150,poll)

if __name__=='__main__':Wizard().mainloop()
