"""Tk-only UI methods; background workers return through a queue."""
import queue,re,threading,tkinter as tk
from tkinter import ttk,messagebox

WORDS={
 'nb': {'check':'Kontroller installasjon','activate':'Ta i bruk og lukk GuToChat…','unavailable':'Installerens aktiveringskontroll er ikke tilkoblet. Du kan fortsatt lagre et oppsettforslag.',
        'checking':'Kontrollerer dagens oppsett og avhengigheter…','ready':'Oppsettet er kontrollert. Ved aktivering lukkes GuToChat før installerens nye kontroll og endring. APRS- og publiseringstillatelser beholdes.',
        'none':'Ingen oppsettendringer å ta i bruk.','failed':'Oppsettet kan ikke tas i bruk ennå. Årsak: {reason}. Dagens oppsett er beholdt.',
        'confirm':'Ta i bruk det kontrollerte oppsettet? GuToChat lukkes først. Installerens arbeid begynner etter at GUI-prosessen er avsluttet. Radiotjenester kan stoppes og startes igjen. Ulagret meldingstekst går tapt.',
        'handoff':'Overfører forslaget til installeren…','title':'Oppsett og enheter','pending':'Klikk «Legg til / oppdater» for å ta med endringene i feltene før installasjonen kontrolleres.'},
 'en': {'check':'Check installation','activate':'Apply and close GuToChat…','unavailable':'Installer activation control is not connected. You can still save a setup proposal.',
        'checking':'Checking current setup and dependencies…','ready':'Setup checked. GuToChat closes before the installer checks again and applies changes. APRS and publication permissions are preserved.',
        'none':'No setup changes to apply.','failed':'Setup cannot be applied yet. Reason: {reason}. Current setup is retained.',
        'confirm':'Apply the checked setup? GuToChat closes first. Installer work starts after the GUI process exits. Radio services may stop and restart. Unsaved message text will be lost.',
        'handoff':'Handing the proposal to the installer…','title':'Setup and devices','pending':'Click “Add / update” to include your edited fields before checking the installation.'}}

def attach(panel,backend,on_close,language):
    panel.control_words=WORDS['en' if language=='en' else 'nb']
    panel.setup_backend=backend;panel.setup_close=on_close
    panel.setup_token=None;panel.setup_busy=False;panel.setup_results=queue.Queue();panel.setup_poll=None
    panel.install_buttons=ttk.Frame(panel);panel.install_buttons.pack(anchor='w',pady=8)
    panel.install_check=ttk.Button(panel.install_buttons,text=panel.control_words['check'],command=lambda:check_installation(panel))
    panel.install_check.pack(side='left',padx=(0,8))
    panel.install_apply=ttk.Button(panel.install_buttons,text=panel.control_words['activate'],command=lambda:activate(panel),state='disabled')
    panel.install_apply.pack(side='left')
    if backend is None:
        panel.install_check.configure(state='disabled')
        panel.status.configure(text=panel.control_words['unavailable'])
    result=getattr(backend,'last_result',None) if backend is not None else None
    if isinstance(result,dict):
        labels={'nb':{'COMPLETE':'Siste oppsettendring er fullført.','ROLLED_BACK':'Siste oppsettendring ble tilbakeført.','FAILED':'Siste oppsettendring feilet. Kontroller installeren før nytt forsøk.','INTERRUPTED_REVIEW_REQUIRED':'Installerens arbeid ble avbrutt. Gjennomgang kreves før nytt forsøk.','WAITING_FOR_GUI_EXIT':'Installeren venter på at forrige GuToChat-prosess avsluttes.','RUNNING':'Installeren arbeider fortsatt.'},'en':{'COMPLETE':'Last setup change completed.','ROLLED_BACK':'Last setup change was rolled back.','FAILED':'Last setup change failed. Check the installer before retrying.','INTERRUPTED_REVIEW_REQUIRED':'Installer work was interrupted. Review is required before retrying.','WAITING_FOR_GUI_EXIT':'Installer is waiting for the previous GuToChat process to exit.','RUNNING':'Installer is still working.'}}
        text=labels['en' if language=='en' else 'nb'].get(result.get('state'))
        if text:panel.status.configure(text=text)
    panel.private.trace_add('write',lambda *_:invalidate(panel))
    panel.enabled.trace_add('write',lambda *_:invalidate(panel))
    for entry in panel.fields.values():
        entry.bind('<KeyRelease>',lambda _:invalidate(panel),add='+')
        entry.bind('<<Paste>>',lambda _:invalidate(panel),add='+')
    panel.bind('<Destroy>',lambda event:destroy(panel,event),add='+')

def invalidate(panel):
    panel.setup_token=None
    if hasattr(panel,'install_apply'):panel.install_apply.configure(state='disabled')
    if getattr(panel,'setup_backend',None):panel.setup_backend.invalidate()

def freeze(panel,value):
    if value:
        panel.setup_saved_states=[]
        def visit(parent):
            for widget in parent.winfo_children():
                if isinstance(widget,ttk.Widget):
                    panel.setup_saved_states.append((widget,widget.state()))
                    widget.state(['disabled'])
                visit(widget)
        visit(panel)
    else:
        for widget,state in panel.setup_saved_states:
            widget.state(['!disabled']);widget.state(state)

def start(panel,kind,action):
    if panel.setup_busy:return
    panel.setup_busy=True;freeze(panel,True)
    panel.status.configure(text=panel.control_words['checking' if kind=='check' else 'handoff'])
    def work():
        try:panel.setup_results.put((kind,action(),None))
        except Exception as error:
            reason=str(error)
            if not re.fullmatch('[A-Z0-9_]{1,100}',reason):reason='SETUP_OPERATION_FAILED'
            panel.setup_results.put((kind,None,reason))
    threading.Thread(target=work,daemon=True).start()
    panel.setup_poll=panel.after(25,lambda:poll(panel))

def poll(panel):
    panel.setup_poll=None
    try:kind,result,error=panel.setup_results.get_nowait()
    except queue.Empty:
        panel.setup_poll=panel.after(25,lambda:poll(panel));return
    panel.setup_busy=False;freeze(panel,False)
    if error:
        invalidate(panel);panel.status.configure(text=panel.control_words['failed'].format(reason=error));return
    if kind=='check':
        if result.get('state')=='NO_CHANGE':
            panel.status.configure(text=panel.control_words['none']);return
        if result.get('state')!='READY' or not result.get('token'):
            invalidate(panel);panel.status.configure(text=panel.control_words['failed'].format(reason='SETUP_CHECK_REQUIRED'));return
        panel.setup_token=result['token'];panel.install_apply.configure(state='normal')
        descriptions=[]
        for change in result.get('changes',[]):
            norwegian=panel.control_words is WORDS['nb']
            if change.get('module')=='private_radio':descriptions.append(('Privat radio' if norwegian else 'Private radio')+': '+(('PÅ' if change.get('enabled') else 'AV') if norwegian else ('ON' if change.get('enabled') else 'OFF')))
            else:
                action=str(change.get('action',''))
                if norwegian:action={'add':'legg til','update':'oppdater','remove':'fjern'}.get(action,action)
                descriptions.append(str(change.get('route_key',''))+': '+action)
        panel.status.configure(text=panel.control_words['ready']+'\n'+'; '.join(descriptions))
    elif result.get('state')=='WAITING_FOR_GUI_EXIT':
        panel.setup_close()
    else:
        invalidate(panel);panel.status.configure(text=panel.control_words['failed'].format(reason='INSTALLER_HANDOFF_NOT_CONFIRMED'))

def check_installation(panel):
    if panel.setup_busy:return
    invalidate(panel)
    if panel.setup_backend is None:
        panel.status.configure(text=panel.control_words['unavailable']);return
    values={key:entry.get().strip() for key,entry in panel.fields.items()}
    if any(values.values()):
        matching=next((d for d in panel.selection['meshtastic_radios'] if d['route_key']==values['route_key']),None)
        if matching is None or any(str(matching[key])!=value for key,value in values.items()) or matching['enabled']!=panel.enabled.get():
            panel.status.configure(text=panel.control_words['pending']);return
    plan=panel.check()
    if plan is not None:start(panel,'check',lambda:panel.setup_backend.prepare(plan))

def activate(panel):
    if panel.setup_busy or panel.setup_backend is None or panel.setup_token is None:return
    if not messagebox.askyesno(panel.control_words['title'],panel.control_words['confirm'],parent=panel):return
    token=panel.setup_token;panel.setup_token=None
    panel.install_apply.configure(state='disabled')
    start(panel,'handoff',lambda:panel.setup_backend.handoff(token))

def destroy(panel,event):
    if event.widget is not panel:return
    if panel.setup_poll is not None:
        try:panel.after_cancel(panel.setup_poll)
        except tk.TclError:pass
        panel.setup_poll=None
