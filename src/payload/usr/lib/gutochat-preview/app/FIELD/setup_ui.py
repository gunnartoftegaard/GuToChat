import copy
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from device_setup import selection_from_config, create_plan, save_plan

TEXT = {
 'nb': ['Oppsett og enheter', 'Velg ønsket oppsett. Kontroller installasjonen før du tar endringer i bruk.',
        'Privat radiosamband (Waveshare eller støttet adapter)', 'Meshtastic-enheter på denne maskinen',
        'Rute-ID', 'Navn', 'API-port', 'Kanal', 'Valgt', 'Legg til / oppdater', 'Fjern valgt',
        'Kontroller forslag', 'Lagre forslag…', 'Tilbakestill til dagens oppsett',
        'SDR, APRS og kartpublisering beholdes som i dagens oppsett. Nye USB-enheter og tjenester må konfigureres før aktivering.',
        'Forslaget er ikke tatt i bruk. Endringer: {count}. Kontrollert aktivering med backup, profilkontroll og USB-/tjenestekontroll gjenstår.',
        'Ugyldig oppsett', 'Forslaget er lagret. Dagens oppsett er uendret.', 'Oppsett',
        'Ikke valgt', 'Velg en rad for å redigere eller fjerne den. Ny rute-ID oppretter en ny enhet. API-porten tilhører en lokal Meshtastic-tjeneste; den oppretter ikke tjenesten.',
        'Fjern den gamle raden først dersom rute-ID skal endres.'],
 'en': ['Setup and devices', 'Choose your setup. Check the installation before applying changes.',
        'Private radio link (Waveshare or supported adapter)', 'Meshtastic devices on this computer',
        'Route ID', 'Name', 'API port', 'Channel', 'Selected', 'Add / update', 'Remove selected',
        'Check proposal', 'Save proposal…', 'Reset to current setup',
        'SDR, APRS and map publication retain their current configuration. New USB devices and services must be configured before activation.',
        'Proposal not applied. Changes: {count}. Controlled activation with backup, profile validation and USB/service checks is still required.',
        'Invalid setup', 'Proposal saved. The current setup is unchanged.', 'Setup',
        'Not selected', 'Select a row to edit or remove it. A new route ID creates a new device. The API port belongs to a local Meshtastic service; it does not create that service.',
        'Remove the old row first when changing its route ID.']}

class SetupPanel(ttk.Frame):
    def __init__(self, parent, config, language):
        super().__init__(parent, padding=12)
        self.config = config
        self.words = TEXT['en' if language == 'en' else 'nb']
        self.selection = selection_from_config(config)
        self.private = tk.BooleanVar(self, value=self.selection['private_radio_enabled'])
        ttk.Label(self, text=self.words[1], wraplength=1000).pack(anchor='w', pady=(0, 12))
        ttk.Checkbutton(self, text=self.words[2], variable=self.private, command=self.invalidate).pack(anchor='w')
        ttk.Label(self, text=self.words[3]).pack(anchor='w', pady=(14, 5))
        self.table = ttk.Treeview(self, columns=('route', 'label', 'port', 'channel', 'enabled'), show='headings', height=6)
        for key, word in zip(self.table['columns'], self.words[4:9]):
            self.table.heading(key, text=word); self.table.column(key, width=160)
        self.table.pack(fill='x'); self.table.bind('<<TreeviewSelect>>', self.select_row)
        form = ttk.Frame(self); form.pack(fill='x', pady=10)
        self.fields = {}
        for column, key in enumerate(('route_key', 'label', 'api_port', 'channel_index')):
            ttk.Label(form, text=self.words[4 + column]).grid(row=0, column=column, sticky='w')
            entry = ttk.Entry(form, width=24 if column < 2 else 10)
            entry.grid(row=1, column=column, padx=(0, 8)); self.fields[key] = entry
        self.enabled = tk.BooleanVar(self, value=True)
        ttk.Checkbutton(form, text=self.words[8], variable=self.enabled).grid(row=1, column=4)
        ttk.Button(form, text=self.words[9], command=self.upsert).grid(row=1, column=5, padx=10)
        ttk.Button(form, text=self.words[10], command=self.remove).grid(row=1, column=6)
        ttk.Label(self, text=self.words[20], wraplength=1050).pack(anchor='w', pady=(0, 12))
        ttk.Label(self, text=self.words[14], wraplength=1050).pack(anchor='w', pady=(0, 12))
        buttons = ttk.Frame(self); buttons.pack(fill='x')
        for index, action in ((11, self.check), (12, self.save), (13, self.reset)):
            ttk.Button(buttons, text=self.words[index], command=action).pack(side='left', padx=(0, 8))
        self.status = ttk.Label(self, text='', wraplength=1050); self.status.pack(anchor='w', pady=12)
        self.refresh_table()
        import os,pathlib
        module_wizard=pathlib.Path('/usr/lib/gutochat-preview/module_setup_ui.py')
        if os.name=='posix' and module_wizard.is_file():
            def open_modules():
                import subprocess
                args=['/usr/bin/python3','-I',str(module_wizard)]
                if language=='en':args.append('--english')
                subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            ttk.Button(buttons,text='Install radio module…' if language=='en' else 'Installer radiomodul…',command=open_modules).pack(side='left',padx=(0,8))

    def invalidate(self):
        if hasattr(self, "setup_backend"):
            from setup_ui_control import invalidate
            invalidate(self)
        self.status.configure(text=self.words[1])

    def refresh_table(self):
        self.table.delete(*self.table.get_children())
        for index, item in enumerate(self.selection['meshtastic_radios']):
            self.table.insert('', 'end', iid=str(index), values=(item['route_key'], item['label'], item['api_port'], item['channel_index'], self.words[8] if item['enabled'] else self.words[19]))
        self.invalidate()

    def select_row(self, event=None):
        selected = self.table.selection()
        if not selected: return
        item = self.selection['meshtastic_radios'][int(selected[0])]
        for key, entry in self.fields.items():
            entry.delete(0, 'end'); entry.insert(0, str(item[key]))
        self.enabled.set(item['enabled'])

    def desired(self):
        result = copy.deepcopy(self.selection)
        result['private_radio_enabled'] = self.private.get()
        return result

    def upsert(self):
        try:
            item = {key: entry.get().strip() for key, entry in self.fields.items()}
            item.update(api_port=int(item['api_port']), channel_index=int(item['channel_index']), enabled=self.enabled.get(), api_host='127.0.0.1')
            selected = self.table.selection()
            if selected and self.selection['meshtastic_radios'][int(selected[0])]['route_key'] != item['route_key']:
                raise ValueError(self.words[21])
            desired = self.desired()
            desired['meshtastic_radios'] = [old for old in desired['meshtastic_radios'] if old['route_key'] != item['route_key']] + [item]
            create_plan(self.config, desired)
            self.selection = desired; self.refresh_table()
        except (ValueError, TypeError) as error:
            messagebox.showerror(self.words[16], str(error), parent=self)

    def remove(self):
        selected = self.table.selection()
        if selected:
            del self.selection['meshtastic_radios'][int(selected[0])]; self.refresh_table()

    def check(self):
        try:
            plan = create_plan(self.config, self.desired())
            self.status.configure(text=self.words[15].format(count=len(plan['changes'])))
            return plan
        except (ValueError, TypeError) as error:
            messagebox.showerror(self.words[16], str(error), parent=self)
            return None

    def save(self):
        plan = self.check()
        if plan is None: return
        path = filedialog.asksaveasfilename(parent=self, title=self.words[12], defaultextension='.json', initialfile='GuToChat_setup_proposal.json', filetypes=[('JSON', '*.json')])
        if not path: return
        try:
            save_plan(path, plan)
            self.status.configure(text=self.words[17])
        except OSError as error:
            messagebox.showerror(self.words[16], str(error), parent=self)

    def reset(self):
        self.selection = selection_from_config(self.config)
        self.private.set(self.selection['private_radio_enabled'])
        for entry in self.fields.values(): entry.delete(0, 'end')
        self.refresh_table()

def add_setup_tab(app):
    app.setup_panel = SetupPanel(app.notebook, app.config, app.ui_language)
    app.notebook.insert(app.help_tab, app.setup_panel, text=app.setup_panel.words[0])
    from setup_ui_control import attach
    backend=app.setup_coordinator
    registered=getattr(backend,'registered_adapters',[]) if backend is not None else []
    if registered:
        from adapter_catalog import merge_registered
        from device_setup import create_plan
        desired=merge_registered(app.setup_panel.selection,registered)
        create_plan(app.config,desired)
        app.setup_panel.selection=desired
        app.setup_panel.refresh_table()
    attach(app.setup_panel, backend, app._close, app.ui_language)
