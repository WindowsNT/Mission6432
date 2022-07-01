Format PE GUI 5.0 DLL
include '..\fasm\include\win32a.inc' ; select your include files for win32
entry DllStart

; Insert your codes and procs here
section '.text' code readable executable


; Exp 1 , takes one parameter
exp1:
push eax
push eax

pop eax
pop eax
ret 4

; This proc must be the entry of a dll
DllStart:
     mov eax,1 ; this proc MUST have TRUE return value
     ret 12; to let kernel loads the requested library

; Imports
section '.idata' import data readable
library user32, 'user32.dll'
import user32, MessageBeep, 'MessageBeep'

; Your functions in code section will exported here
section '.edata' export readable
export 'fasmdll.dll',exp1,'exp1'

