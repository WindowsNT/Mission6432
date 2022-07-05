Format PE GUI 5.0 DLL
include '..\fasm\include\win32a.inc'
entry DllStart


; Imports 
section '.idata' import data readable
library kernel32, 'kernel32.dll', libtest, 'library.dll'
import kernel32, GetCurrentProcess, 'GetCurrentProcess'
import libtest, exp1, 'exp1'



; Insert your codes and procs here
section '.text' code readable executable


; Exp 2 , takes one parameter
exp2:
push eax
push eax


push eax
call [exp1]

pop eax
pop eax
ret 4

; This proc must be the entry of a dll
DllStart:
     mov eax,1 ; this proc MUST have TRUE return value
     ret 12; to let kernel loads the requested library


; Your functions in code section will exported here
section '.edata' export readable
export 'fasmdll.dll',exp2,'exp2'

