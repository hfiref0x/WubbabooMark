;*******************************************************************************
;
;  (C) COPYRIGHT AUTHORS, 2023
;
;  TITLE:       NTCALL.ASM
;
;  VERSION:     1.00
;
;  DATE:        20 Jun 2023
;
;  NT system call stubs, x64.
;
; THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
; ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
; TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
; PARTICULAR PURPOSE.
;
;*******************************************************************************/

_DATA$00 SEGMENT PARA 'DATA'

PUBLIC KiSystemCallNumber
PUBLIC KiSystemCallAddress

KiSystemCallAddress label qword
	dq  0
KiSystemCallNumber label dword
	dd  0

_DATA$00 ENDS

_TEXT$00 segment para 'CODE'

	ALIGN 16
	PUBLIC SkiDirectSystemCall
	PUBLIC SkiIndirectSystemCall

SkiDirectSystemCall PROC
	mov r10, rcx
	mov eax, KiSystemCallNumber
	syscall
	ret
SkiDirectSystemCall ENDP

SkiIndirectSystemCall PROC
	mov r10, rcx
	mov eax, KiSystemCallNumber
	jmp qword ptr [KiSystemCallAddress]
SkiIndirectSystemCall ENDP

_TEXT$00 ENDS
	
END
