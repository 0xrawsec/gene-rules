################################################################################
#                              Regex templates                                 #
# Format:                                                                      #
#  TEMPLATE_NAME: 'REGULAR_EXPRESSION'                                         #
# Use template in rule:                                                        #
#  put {{TEMPLATE_NAME}} where you want the template to be used                #
## Some best practices                                                         #
# * Try to avoid matching end of line ($) in template                          #
################################################################################

# Paths
windows: '(?i:C:\\Windows\\)'
system: '(?i:C:\\Windows\\Sys(wow64|tem32)\\)'
systemapps: '(?i:C:\\Windows\\SystemApps\\)'
programfiles: '(?i:C:\\(PROGRA~2|Program Files.*?)\\)'
## Likely AppV default path
## if not using AppV replace by '^$'
appv: '(?i:C:\\ProgramData\\AppV\\)'

## Temp folders
temp: '(?i:(C:\\Windows\\Temp\\|C:\\Users\\.*\\AppData\\Local\\Temp\\))'

# Regular expression matching private IP addresses ranges
priv-ipv4: '(?i:(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.))'

#Browser related
browsers: '(?i:\\(iexplore|firefox|chrome|MicrosoftEdge|opera|vivaldi)\.exe)'

#Extensions
script-exts: '(?i:(\.ps1|\.bat|\.cmd|\.vb|\.vbs|\.vbscript|\.vbe|\.js|\.jse|\.ws|\.wsf))'
exec-exts: '(?i:(\.acm|\.ax|\.com|\.cpl|\.dic|\.dll|\.drv|\.ds|\.efi|\.exe|\.grm|\.iec|\.ime|\.lex|\.msstyles|\.mui|\.ocx|\.olb|\.rll|\.rs|\.scr|\.sys|\.tlb|\.tsp|\.winmd|\.node))'

# Exe to monitor
suspicious: '(?i:\\(certutil|rundll32|powershell|wscript|cscript|cmd|mshta|regsvr32|msbuild|installutil|regasm)\.exe)'

decode: '(?i:\\(certutil)\.exe)'

execution: '(?i:\\(rundll32|powershell|wscript|cscript|cmd|mshta|regsvr32|msbuild|installutil|regasm|dnx|rcsi|WinDbg|cdb|tracker|cmstp|msiexec|mavinject|SyncAppvPublishingServer|Odbcconf|msxsl|wmic)\.exe)'

admintools: '(?i:\\(ping|systeminfo|net1?|xcopy|nbtstat|bitsadmin|netstat|powershell|cmd|cscript|wscript|arp|at|certutil|dsquery|ipconfig|netsh|reg|route|schtasks|wusa|wmic|sc|rundll32|qprocess|tasklist|query)\.exe$)'

# MSOffice Images
msoffice: '(?i:\\(excel|winword|powerpnt|outlook)\.exe)'

# WebServers
# binaries taken from: https://github.com/Neo23x0/sigma/blob/99b15edf8add183543ca5738ec93f87416c34bd9/rules/windows/process_creation/win_webshell_detection.yml
webservers: '(?:\\(tomcat.*?|w3wp|php-cgi|nginx|httpd|apache.*?)\.exe)'

# Signatures for drivers and DLLs
trusted-drv-sig: '^(Microsoft Windows)$'
trusted-dll-sig: '^(Microsoft Windows|Microsoft Corporation|Microsoft Windows Component Publisher|Microsoft Windows Publisher|Microsoft Windows 3rd party Component)$'

# Sysmon related
sysmon-svc: 'Sysmon64'

# Windows 10 services
# sc.exe query type= service state= all
win10shared: '(?i:(^|,)(AJRouter|AppIDSvc|AppMgmt|AssignedAccessManagerSvc|AxInstSV|BDESVC|BFE|BrokerInfrastructure|BTAGService|bthserv|CertPropSvc|CoreMessagingRegistrar|CscService|DcomLaunch|DeviceAssociationService|DevQueryBroker|diagsvc|DisplayEnhancementService|dmwappushservice|dot3svc|DsSvc|Eaphost|EFS|embeddedmode|EntAppSvc|fdPHost|FDResPub|fhsvc|FrameServer|GraphicsPerfSvc|hidserv|HvHost|icssvc|IKEEXT|IpxlatCfgSvc|KeyIso|KtmRm|lltdsvc|LxpSvc|mpssvc|MSiSCSI|NaturalAuthentication|NcaSvc|NcdAutoSetup|Netlogon|Netman|NetSetupSvc|NetTcpPortSharing|p2pimsvc|p2psvc|PeerDistSvc|pla|PNRPAutoReg|PNRPsvc|PolicyAgent|Power|PrintNotify|QWAVE|RasAuto|RasMan|RemoteAccess|RemoteRegistry|RetailDemo|RmSvc|RpcEptMapper|RpcSs|SamSs|SCardSvr|ScDeviceEnum|SCPolicySvc|seclogon|SensorService|SensrSvc|SessionEnv|SharedAccess|SharedRealitySvc|shpamsvc|SmsRouter|svsvc|SystemEventsBroker|TapiSrv|TermService|TroubleshootingSvc|tzautoupdate|UmRdpService|upnphost|VaultSvc|vmicguestinterface|vmicheartbeat|vmickvpexchange|vmicrdv|vmicshutdown|vmictimesync|vmicvmsession|vmicvss|W32Time|WalletService|WbioSrvc|wcncsvc|WebClient|Wecsvc|WEPHOSTSVC|wercplsupport|WFDSConMgrSvc|WiaRpc|WinRM|wlpasvc|WManSvc|workfolderssvc|WwanSvc|XblAuthManager|XblGameSave|XboxGipSvc|XboxNetApiSvc|AarSvc_\w+|BcastDVRUserService_\w+|BluetoothUserService_\w+|CaptureService_\w+|ConsentUxUserSvc_\w+|DeviceAssociationBrokerSvc_\w+|DevicePickerUserSvc_\w+|DevicesFlowUserSvc_\w+|MessagingService_\w+|OneSyncSvc_\w+|PimIndexMaintenanceSvc_\w+|PrintWorkflowUserSvc_\w+|UnistoreSvc_\w+|UserDataSvc_\w+)(,|$))'

win10svcs: '(?i:^(ALG|Appinfo|AppReadiness|AppVClient|AppXSvc|AudioEndpointBuilder|Audiosrv|autotimesvc|BITS|BthAvctpSvc|camsvc|CDPSvc|ClipSVC|COMSysApp|CryptSvc|defragsvc|DeviceInstall|Dhcp|diagnosticshub.standardcollector.service|DiagTrack|DispBrokerDesktopSvc|DmEnrollmentSvc|Dnscache|DoSvc|DPS|DsmSvc|DusmSvc|EventLog|EventSystem|Fax|FontCache|gpsvc|InstallService|iphlpsvc|LanmanServer|LanmanWorkstation|lfsvc|LicenseManager|lmhosts|LSM|MapsBroker|MSDTC|msiserver|NcbService|netprofm|NgcCtnrSvc|NgcSvc|NlaSvc|nsi|PcaSvc|perceptionsimulation|PerfHost|PhoneSvc|PlugPlay|ProfSvc|PushToInstall|RpcLocator|Schedule|SDRSVC|SecurityHealthService|SEMgrSvc|SENS|Sense|SensorDataService|SgrmBroker|ShellHWDetection|smphost|SNMPTRAP|spectrum|Spooler|sppsvc|SSDPSRV|ssh-agent|SstpSvc|StateRepository|stisvc|StorSvc|swprv|SysMain|TabletInputService|Themes|TieringEngineService|TimeBrokerSvc|TokenBroker|TrkWks|TrustedInstaller|UevAgentService|UserManager|UsoSvc|VacSvc|vds|VSS|WaaSMedicSvc|WarpJITSvc|wbengine|Wcmsvc|WdiServiceHost|WdiSystemHost|WdNisSvc|WerSvc|WinDefend|WinHttpAutoProxySvc|Winmgmt|wisvc|WlanSvc|wlidsvc|wmiApSrv|WMPNetworkSvc|WpcMonSvc|WPDBusEnum|WpnService|wscsvc|WSearch|wuauserv|cbdhsvc_\w+|CDPUserSvc_\w+|WpnUserService_\w+)$)'

# Common registry regexp
SOFTWARE: '(?i:\\SOFTWARE(\\WOW6432Node)??)'
HKCR: '(?i:HKCR(\\WOW6432Node)??)'