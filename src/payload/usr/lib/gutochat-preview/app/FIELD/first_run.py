"""Core-only first-install choices. No system changes or hardware discovery."""
import json,pathlib

def choices(role,language):
    if role not in ('base','field') or language not in ('nb','en'):raise ValueError('FIRST_INSTALL_INVALID_SELECTION')
    return {'schema_version':1,'role':role,'language':language,'modules':['core'],'publication':'OFF'}

def validate(value):
    if not isinstance(value,dict) or set(value)!={'schema_version','role','language','modules','publication'}:raise ValueError('FIRST_INSTALL_INVALID_PROPOSAL')
    expected=choices(value['role'],value['language'])
    if type(value['schema_version']) is not int or value!=expected:raise ValueError('FIRST_INSTALL_INVALID_PROPOSAL')
    return expected

def core_config(proposal,data_directory,port):
    proposal=validate(proposal);folder=pathlib.Path(data_directory)
    if not folder.is_absolute() or '..' in folder.parts:raise ValueError('FIRST_INSTALL_ABSOLUTE_DATA_PATH_REQUIRED')
    if type(port) is not int or not 1024<=port<=65535:raise ValueError('FIRST_INSTALL_INVALID_PORT')
    return {'role':proposal['role'],'address':1 if proposal['role']=='base' else 2,
            'node_name':'GuToChat '+proposal['role'].capitalize(),'station_name':'GuToChat',
            'ui_language':proposal['language'],'private_radio_enabled':False,
            'meshtastic_radios':[],'meshtastic_gateways':[],
            'api_host':'127.0.0.1','api_port':port,
            'database':str(folder/'core.sqlite'),'contacts_file':str(folder/'contacts.json'),
            'ui_state_file':str(folder/'ui.json'),'offline_map_directory':str(folder/'maps'),
            'map_aprs_database':str(folder/'aprs.sqlite'),'map_aprs_live_enabled':False,
            'map_aprs_headless_enabled':False,'ui_refresh_interval_seconds':60}

def save_proposal(path,proposal):
    proposal=validate(proposal)
    with pathlib.Path(path).open('x',encoding='utf-8') as output:json.dump(proposal,output,indent=2);output.write('\n')

TEXT={
 'nb':{'title':'GuToChat – første oppsett','language':'Språk','role':'Velg rolle','base':'Base','field':'Field',
       'base_help':'Base kan senere kobles til lokale radioer og andre støttede enheter.',
       'field_help':'Field kan senere kobles til et støttet radiosamband med Base.',
       'scope':'Start med grunnprogrammet. Ingen radio eller SDR er nødvendig. Du kan legge til støttede enheter senere.',
       'privacy':'APRS og kartpublisering er avslått. Oppsettet sender ingen radiotrafikk.',
       'save':'Lagre installasjonsvalg…','cancel':'Avbryt','saved':'Valgene er lagret. Administratorinstallasjonen gjenstår.',
       'error':'Kunne ikke lagre valgene. Velg en ny fil; eksisterende filer erstattes ikke.'},
 'en':{'title':'GuToChat – first setup','language':'Language','role':'Choose a role','base':'Base','field':'Field',
       'base_help':'Base can later connect to local radios and other supported devices.',
       'field_help':'Field can later connect to a supported radio link with Base.',
       'scope':'Start with the core application. No radio or SDR is required. You can add supported devices later.',
       'privacy':'APRS and map publication are off. This setup sends no radio traffic.',
       'save':'Save installation choices…','cancel':'Cancel','saved':'Choices saved. Administrator installation is still required.',
       'error':'Could not save the choices. Choose a new file; existing files are not replaced.'}}

def make_window():
    import tkinter as tk
    from tkinter import ttk,filedialog,messagebox
    class FirstSetup(tk.Tk):
        def __init__(self):
            super().__init__();self.language=tk.StringVar(self,value='nb');self.role=tk.StringVar(self,value='base')
            self.frame=ttk.Frame(self,padding=22);self.frame.pack(fill='both',expand=True)
            self.render();self.resizable(False,False)
        def proposal(self):return choices(self.role.get(),self.language.get())
        def render(self):
            for child in self.frame.winfo_children():child.destroy()
            words=TEXT[self.language.get()];self.title(words['title'])
            ttk.Label(self.frame,text=words['title'],font=('Arial',16,'bold')).pack(anchor='w',pady=(0,18))
            bar=ttk.Frame(self.frame);bar.pack(fill='x',pady=(0,16))
            ttk.Label(bar,text=words['language']).pack(side='left')
            for label,value in [('Norsk','nb'),('English','en')]:
                ttk.Radiobutton(bar,text=label,value=value,variable=self.language,command=self.render).pack(side='left',padx=14)
            ttk.Label(self.frame,text=words['role']).pack(anchor='w')
            for role in ('base','field'):
                ttk.Radiobutton(self.frame,text=words[role],value=role,variable=self.role).pack(anchor='w',pady=(8,0))
                ttk.Label(self.frame,text=words[role+'_help'],wraplength=590).pack(anchor='w',padx=22)
            ttk.Label(self.frame,text=words['scope'],wraplength=620).pack(anchor='w',pady=(20,10))
            ttk.Label(self.frame,text=words['privacy'],wraplength=620).pack(anchor='w')
            buttons=ttk.Frame(self.frame);buttons.pack(fill='x',pady=(24,0))
            ttk.Button(buttons,text=words['save'],command=self.save).pack(side='left')
            ttk.Button(buttons,text=words['cancel'],command=self.destroy).pack(side='right')
        def save(self):
            words=TEXT[self.language.get()]
            target=filedialog.asksaveasfilename(parent=self,defaultextension='.json',initialfile='gutochat-installation.json',filetypes=[('JSON','*.json')])
            if not target:return
            try:save_proposal(target,self.proposal())
            except (OSError,ValueError):messagebox.showerror(words['title'],words['error'],parent=self);return
            messagebox.showinfo(words['title'],words['saved'],parent=self)
    return FirstSetup()

if __name__=='__main__':make_window().mainloop()
