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
exec-exts: '(?i:(\.acm|\.ax|\.com|\.cpl|\.dic|\.dll|\.drv|\.ds|\.efi|\.exe|\.grm|\.iec|\.ime|\.lex|\.msstyles|\.mui|\.ocx|\.olb|\.rll|\.rs|\.scr|\.sys|\.tlb|\.tsp))'

# Exe to monitor
suspicious: '(?i:\\(certutil|rundll32|powershell|wscript|cscript|cmd|mshta|regsvr32|msbuild|installutil|regasm)\.exe)'
msoffice: '(?i:\\(excel|winword|powerpnt|outlook)\.exe)'
