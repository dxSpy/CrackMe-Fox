format PE GUI on 'stub.exe'
entry Main

include 'win32a.inc'

randseed = %t
macro randomize {
randseed = randseed * 1103515245 + 12345
randseed = (randseed / 65536) mod 0x100000000
rndnum = randseed and 0xFFFFFFFF
}

;--------------------------------------------------------------
	ID_BTN_UPDATE equ 101
;--------------------------------------------------------------	
	randomize
	MAIN_KEY_XOR_DATA = rndnum mod 0xFF
	
	randomize	
	DATA_KEY_XOR_DATA = rndnum mod 0xFF
;--------------------------------------------------------------

macro crypt start,length,key { 
	local x,y,key_size,key_pos 
	virtual at 0 
		db key 
	key_size = $ 
	end virtual 	
	key_pos = 0 
	repeat length	
		load x from start+%-1	
			virtual at 0 
			  db key
			  load y from key_pos
			end virtual 		
			x = x xor y		
		store x at start+%-1 		
		key_pos = key_pos + 1 	
		if key_pos >= key_size 
		  key_pos = 0 
		end if 		
	end repeat 
}

;--------------------------------------------------------------
section '.code' code executable readable writeable

proc Main
	mov  eax,MAIN_KEY_XOR_DATA
	mov  ebx,start_main
	mov  edx,end_main
	push XorCodeUnPack
	pop  ecx
	call ecx
endp

proc XorCodeUnPack
	push  edx ebx eax  ; edx конец функции, ebx начало, eax - ключ
@@: xor   [ebx],eax    ; ксорим байтики
	inc   ebx          ; Следуший байт
	cmp   ebx,edx      ; конец?	
	jb    @b           ; нет: продолжаем
	pop   eax ebx edx
	call  ebx
endp

start_main:
	mov      eax,DATA_KEY_XOR_DATA	
	mov      ebx,start_data
	mov      edx,end_data
	stdcall  CryptXorData

	invoke GetModuleHandleA,0
	mov	   [wc.hInstance],eax
	
	invoke LoadIconA,eax,2
	mov    [wc.hIcon],eax

	invoke LoadCursorA,0,IDC_ARROW
	mov    [wc.hCursor],eax
	
	invoke RegisterClassA,wc

	
	invoke GetSystemMetrics,SM_CXSCREEN
	sub    eax,[_nWndWidth]
	shr    eax,1
	mov    [_nXscreen],eax
		
	invoke GetSystemMetrics,SM_CYSCREEN
	sub    eax,[_nWndHeight]
	shr    eax,1
	mov    [_nYscreen],eax

	invoke CreateWindowExA,WS_EX_DLGMODALFRAME ,_sClass,_sTitle,WS_VISIBLE+WS_SYSMENU,[_nXscreen],[_nYscreen],[_nWndWidth],[_nWndHeight],0,0,[wc.hInstance],0
	
msg_loop:
	invoke GetMessageA,msg,0,0,0
	test   eax,eax
	je     end_loop
	invoke TranslateMessage,msg
	invoke DispatchMessageA,msg
	jmp    msg_loop
end_loop:
	invoke ExitProcess,[msg.wParam]

proc WindowProc hwnd,wMsg,wParam,lParam
	push ebx esi edi
	mov  eax,[wMsg]
	cmp	 eax,WM_CREATE
	je  .wmCreate
	cmp  eax,WM_COMMAND
	je  .wmCommand
	cmp  eax,WM_DESTROY
	je  .wmDestroy
.defwndproc:
	invoke DefWindowProcA,[hwnd],[wMsg],[wParam],[lParam]
	jmp	   .finish
.wmCreate:
	invoke CreateWindowExA,0,_sClassBtn,_sBtnCheck,WS_VISIBLE+WS_CHILD+BS_FLAT,10,10,275,40,[hwnd],ID_BTN_UPDATE,0,0
	
	invoke CreateWindowExA,WS_EX_CLIENTEDGE,_sClassEdit,_sTitleEdt,WS_VISIBLE+WS_CHILD+ES_CENTER+ES_PASSWORD,10,60,275,23,[hwnd],0,0,0
	mov    [_hBtnCheck],eax
	
	xor eax,eax 
	jmp .finish
.wmCommand:
	stdcall OnCommand,[wParam],[hwnd]	
	
	xor eax,eax 
	jmp .finish
.wmDestroy:
	invoke PostQuitMessage,0
	xor	eax,eax
.finish:
	pop	edi esi ebx
	ret
endp

proc OnCommand wParam:DWORD, hWnd:DWORD
	mov eax,[wParam]
	cmp	eax,ID_BTN_UPDATE
	je	.upd
	jmp @f
.upd:
	invoke  GetWindowTextLengthA,[_hBtnCheck]
	inc     eax
	invoke  GetWindowTextA, [_hBtnCheck], buffEdtTmp, eax
	
	invoke  lstrlenA,buffEdtTmp
	
	mov     [sizehash],eax
	stdcall Adler32,buffEdtTmp,eax
	
	cmp  eax,[_sKeyHash]
	jne  @NotGood
	
	stdcall fletcher,buffEdtTmp,[sizehash]

	shr 	 eax,0xC9	
	mov      ebx,start_code
	mov      edx,end_code
	stdcall  CryptXorCode
	
	jmp @f
@NotGood:
	stdcall myMsg, _sInvalidK, 0h
    invoke  MessageBoxA,[hWnd],_sInvalidK,_sInvalidK,0
	stdcall myMsg, _sInvalidK, 0h
@@: ret
endp

proc GetRandomNumber minValue:DWORD, maxValue:DWORD
	push	ebx ecx edx
	mov		eax, [seed]
	or		eax, eax
	jnz		@2
@1:
	invoke	GetTickCount 
	or		eax, eax
	jz		@1
@2:
	xor		edx, edx
	mov		ebx, 127773
	div		ebx
	push	eax 
	mov		eax, 16807
	mul		edx 
	pop		edx 
	push	eax 
	mov		eax, 2836 
	mul		edx 
	pop		edx 
	sub		edx, eax 
	mov		eax, edx 
	mov		[seed], edx
	xor		edx, edx
	mov		ebx, [maxValue]
	sub		ebx, [minValue]
	inc		ebx
	div		ebx
	mov		eax, edx
	add		eax, [minValue]
	pop		edx ecx ebx
    ret
endp

proc Adler32 lpData:DWORD, dSize:DWORD
	push    ebx ecx edx esi edi 	; Инициализация
	mov     edi,1           		; s1 = 1
	xor     esi,esi        			; s2 = 0
	cmp     [dSize],0       		; Длина строки
	je      @ret	
	mov     ebx,65521       		; base
	xor     ecx,ecx
@@: mov     eax,[lpData]    		; Получить символ из строки
	movzx   eax,byte[eax+ecx]
	add     eax,edi         		; s1 = (s1 + buf[i]) % 65521
	xor     edx,edx
	div     ebx
	mov     edi,edx
	add     edx,esi        			; s2 = (s2 + s1) % 65521
	mov     eax,edx
	xor     edx,edx
	div     ebx
	mov     esi,edx
	inc     ecx            			; Следующий символ
	cmp     ecx,[dSize]
	jb      @b
@ret: 
	mov     eax,esi        			; adler32 = (s2 << 16) + s1
	rol     eax,16
	add     eax,edi
	pop     edi esi edx ecx ebx
	ret
endp

proc fletcher lpData:DWORD, dSize:DWORD
	push    ebx ecx esi     ; Инициализация      
	xor     ebx,ebx      
	mov     ecx,[dSize]     ; Длина строки
	or      ecx,ecx
	jz      .loc_ret   
	mov     esi,[lpData]    ; Указатель на начало строки
.loc_checksum:              ; Хеширование
	lodsb
	add     bl,al
	add     bh,bl
	loop    .loc_checksum
.loc_ret:
	movzx   eax,bx 
	pop     esi ecx ebx	
	ret
endp

proc myMsg  Text:DWORD, Key:DWORD
	mov     esi,[Text]  ; Инициализация esi
	mov     edi,esi     ; Сохраняем в edi
	mov     ebx,[Key] ; Инициализация ebx Ключом
@@: lodsb               ; Загрузить строковый операнд в AL 
	or      al,al       ; Сравнение на 0
	je      @f  	    ; Если 0 прыгаем на выход
	inc     ebx			; Иначи берем следуший байт
	xor     eax,ebx	    ; ксорим байтики
	stosb               ; STOS пересылает содержимое регистра AL, AX или EAX в байт, слово в памяти, в регистр EDI
	jmp     @b          ; продолжаем    
@@: ret					; Выход
endp
	
;shr 	 eax,0xC8	    - Key 
;mov     ebx,start_code - Start
;mov     edx,end_code   - End
;stdcall CryptXorCode	
proc CryptXorCode
	push  eax edx ebx ebx  ; EАХ - Ключ, EВХ начало, EBX адрес возврата
@@: xor   [ebx],eax    	   ; ксорим байтики
	inc   ebx              ; Следуший байт
	cmp   ebx,edx          ; конец?	
	jb    @b               ; нет: продолжаем	
	pop   ebx              ; иначе: берём адрес процедуры	
	call  ebx              ; выполнить EВХ! (возвратимся ниже /адрес возврата/)
	pop   ebx edx eax      ; подготовка к шифрованию..
	jmp   @b               ; зашифровываем процедуру обратно!
endp

proc CryptXorData
	push  eax edx ebx  ; EАХ - Ключ, EВХ начало, EBX адрес возврата
@@: xor   [ebx],eax    ; ксорим байтики
	inc   ebx          ; Следуший байт
	cmp   ebx,edx      ; конец?	
	jb    @b           ; нет: продолжаем
	pop   eax ebx edx ebx
	call  ebx
endp

start_code:
	stdcall myMsg, _sGood, 5h
	push    0
	push    _sGood
	push    _sGood
	push    0
    call    [MessageBoxA]
	stdcall myMsg, _sGood, 5h
	ret
	_sGood  db 'G' xor 0x6, 'o' xor 0x7, 'o' xor 0x8, 'd' xor 0x9, ' ' xor 0xA, 'W' xor 0xB, 'o' xor 0xC, 'r' xor 0xD, 'k' xor 0xE, 0x0	
end_code:
crypt start_code,end_code - start_code,0x53

end_main: 
crypt start_main,end_main - start_main,MAIN_KEY_XOR_DATA

;===========================================================================
;======== Data 
include 'data\rdata.inc'
;===========================================================================
;======== Import Data
include 'data\idata.inc'
;===========================================================================
;======== Rsrc Data
include 'data\rsrc.inc'