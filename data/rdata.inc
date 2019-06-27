;===========================================================================
;======== Data
section '.data' data readable writeable
    start_data: ;-----------------------------------------------------------
	_sInvalidK  db 'I' xor 0x1, 'n' xor 0x2, 'v' xor 0x3, 'a' xor 0x4, 'l' xor 0x5, 'i' xor 0x6, 'd' xor 0x7, ' ' xor 0x8 , 'K' xor 0x9, 'e' xor 0xA, 'y' xor 0xB, 0x0

	_sTitle     db 'CrackMe Fox #1',0
	_sClass     db 'Class32',0
	
	_sTitleEdt  db 'Key',0
	_sBtnCheck  db 'Cheak',0

	_sClassBtn  db 'BUTTON',0
	_sClassEdit db 'EDIT',0
	
	buffEdtTmp  rb 20
		
    sizehash    dd ? 	
	_sKeyHash   dd 0x18B103A6 ; 'Yougame1337'
		
	_hBtnCheck  dd ?
	
	_nXscreen   dd ?
	_nYscreen   dd ?
	_nWndWidth  dd 300
	_nWndHeight dd 120
	
	wc WNDCLASS 0,WindowProc,0,0,NULL,NULL,NULL,5+1,NULL,_sClass

	msg MSG
	
	seed        dd ?
	
	end_data: ;-----------------------------------------------------------

	crypt start_data,end_data - start_data,DATA_KEY_XOR_DATA
