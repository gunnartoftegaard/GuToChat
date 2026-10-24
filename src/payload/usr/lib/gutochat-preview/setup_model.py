"""Strict wizard commands and translated outcomes; no shell or UI side effects."""
import json,re
CODE='/usr/lib/gutochat-preview'
TEXT={
 'nb':dict(title='GuToChat – grunnoppsett',language='Språk',role='Velg rolle',
  scope='Start uten radio eller SDR. Støttede enheter kan legges til senere. APRS og kartpublisering er avslått.',
  install='Installer nytt oppsett',resume='Gjenoppta oppsett',deactivate='Deaktiver oppsett',close='Lukk',
  help='Installer lager et nytt grunnoppsett. Gjenoppta starter et tidligere registrert oppsett og beholder det opprinnelige språket. Deaktiver stopper bare den valgte rollens tjenester og bevarer konfigurasjon og data. Selve programpakken fjernes via systemets pakkebehandler.',
  confirm='Fortsette med «{action}» for {role}? Systemet ber om administratorbekreftelse.',
  busy='Venter på administratorbekreftelse eller fullføring …',idle='Velg rolle og handling.',
  success='Handlingen er fullført.',cancelled='Administratorbekreftelsen ble avbrutt. Ingen ny handling er startet.',
  auth='Administratorbekreftelsen mislyktes. Kontroller at skrivebordet har en aktiv godkjenningstjeneste.',
  failed='Handlingen ble ikke fullført. Data er bevart. Feilkode: {reason}',
  existing='Det finnes allerede et oppsett. Bruk Gjenoppta. Et ufullstendig oppsett må undersøkes før det erstattes.',
  missing='Det finnes ikke et fullstendig registrert oppsett for denne rollen. Installer nytt, eller få et ufullstendig oppsett undersøkt.',
  locked='En annen oppsettsjobb kjører. Vent til den er ferdig og prøv igjen.',
  changed='Oppsettet har endringer som må undersøkes før tjenestene kan startes eller stoppes.',
  os='Denne interne prøvepakken kan prøves på Ubuntu 24.04 og Raspberry Pi med 64-bits Debian 13. Andre systemer er ikke godkjent ennå.',
  dependencies='Nødvendige programpakker mangler. Installer GuToChat-pakken via systemets pakkebehandler.',
  start='Oppstarten ble ikke bekreftet. Bruk Gjenoppta etter at årsaken er undersøkt.'),
 'en':dict(title='GuToChat – core setup',language='Language',role='Choose a role',
  scope='Start without a radio or SDR. Supported devices can be added later. APRS and map publication are off.',
  install='Install new setup',resume='Resume setup',deactivate='Deactivate setup',close='Close',
  help='Install creates a new core setup. Resume starts a previously registered setup and retains its original language. Deactivate stops only the selected role’s services and retains configuration and data. Remove the application package using the system package manager.',
  confirm='Continue with “{action}” for {role}? The system will request administrator authentication.',
  busy='Waiting for administrator authentication or completion …',idle='Choose a role and action.',
  success='The operation is complete.',cancelled='Administrator authentication was cancelled. No new operation was started.',
  auth='Administrator authentication failed. Check that the desktop has an active authentication agent.',
  failed='The operation did not complete. Data is retained. Error code: {reason}',
  existing='A setup already exists. Use Resume. An incomplete setup must be reviewed before replacement.',
  missing='No complete registered setup exists for this role. Install a new setup, or have an incomplete setup reviewed.',
  locked='Another setup job is running. Wait for it to finish and try again.',
  changed='The setup has changes that need review before services can be started or stopped.',
  os='This internal preview can be tested on Ubuntu 24.04 and Raspberry Pi with 64-bit Debian 13. Other systems have not been approved yet.',
  dependencies='Required packages are missing. Install the GuToChat package using the system package manager.',
  start='Startup was not confirmed. Use Resume after the cause has been investigated.')}

def command(action,role,language,username):
    if action not in ('install','resume','deactivate') or role not in ('base','field') or language not in TEXT:
        raise ValueError('INVALID_SELECTION')
    if not isinstance(username,str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',username):raise ValueError('INVALID_ACCOUNT')
    args=['/usr/bin/pkexec','/usr/bin/python3','-I',CODE+'/admin.py']
    return args+(['setup',role,language,username] if action=='install' else [action,role])

def outcome(code,stdout,language):
    words=TEXT[language]
    if code==126:return False,words['cancelled']
    if code==127:return False,words['auth']
    try:result=json.loads(stdout)
    except (TypeError,ValueError):return False,words['failed'].format(reason='INVALID_RESULT')
    if code==0 and isinstance(result,dict):
        if result.get('state')=='INSTALLED':return True,words['success']
        roles=result.get('roles')
        if isinstance(roles,list) and len(roles)==1 and isinstance(roles[0],dict) and roles[0].get('state') in ('DEACTIVATED','NOT_CONFIGURED'):
            return True,words['success']
    reason=result.get('reason','OPERATION_FAILED') if isinstance(result,dict) else 'INVALID_RESULT'
    lookup={'EXISTING_INSTALLATION_REVIEW_REQUIRED':'existing','ADMIN_JOB_RUNNING':'locked',
            'REGISTRATION_MISSING':'missing','PREVIEW_REQUIRES_SUPPORTED_OS':'os','DEPENDENCIES_MISSING':'dependencies',
            'BROKER_READY_TIMEOUT':'start','CORE_HEALTH_CHECK_FAILED':'start','SERVICE_NOT_ACTIVE':'start'}
    if isinstance(reason,str) and reason in lookup:return False,words[lookup[reason]]
    if reason in ('UNIT_MODIFIED_REVIEW_REQUIRED','UNIT_TEMPLATE_CHANGED_REVIEW_REQUIRED','REGISTERED_ACCOUNT_CHANGED','REGISTRY_CHANGED','CORE_ONLY_CONFIGURATION_REQUIRED','DATA_OWNER_CHANGED'):
        return False,words['changed']
    safe=reason if isinstance(reason,str) and re.fullmatch(r'[A-Z_]{1,80}',reason) else 'OPERATION_FAILED'
    return False,words['failed'].format(reason=safe)
