;===========================================================================
;======== Import Data 
section '.idata' data import readable
	dd 0,0,0,rva kernel_name,rva kernel32_table
	dd 0,0,0,rva user32_name,rva user32_table
	dd 0,0,0,rva ntdll_name, rva ntdll_table
	dd 0,0,0,0,0
	;--------------------------------
	;----------------
	
	;--------------------------------
	;----------------
	ntdll_table:
		;NtReleaseMutant dd RVA _NtReleaseMutant
	dd 0
	
	ntdll_name 	db 'ntdll.dll',0	
		;_NtReleaseMutant db 0,0,'NtReleaseMutant',0		
	dd 0

	;--------------------------------
	;----------------
	kernel32_table:
		GetModuleHandleA  	  dd rva _GetModuleHandleA
		ExitProcess  	      dd rva _ExitProcess	
		lstrlenA     	 	  dd rva _lstrlenA
		GetTickCount 	  	  dd rva _GetTickCount
		GetSystemTime 	  	  dd rva _GetSystemTime
		GetSystemTime_ 	  	  dd rva _GetSystemTime_
	dd 0
	kernel_name          	    db 'kernel32.dll',0
		_GetModuleHandleA 		db 0,0,'GetModuleHandleA',0
		_ExitProcess      	    db 0,0,'ExitProcess',0
		_lstrlenA         		db 0,0,'lstrlenA',0
		_GetTickCount    	    db 0,0,'GetTickCount',0
		_GetSystemTime    	    db 0,0,'GetSystemTime',0
		_GetSystemTime_    	    db 0,0,'GetSystemTime',0
	dd 0
	
	;--------------------------------
	;----------------
	user32_table:
		MessageBoxA 	 	 dd rva _MessageBoxA
		LoadIconA   	 	 dd rva _LoadIconA
		LoadCursorA 	     dd rva _LoadCursorA
		RegisterClassA 	     dd rva _RegisterClassA
		CreateWindowExA      dd rva _CreateWindowExA
		DefWindowProcA 	     dd rva _DefWindowProcA
		PostQuitMessage      dd rva _PostQuitMessage
		GetMessageA 	     dd rva _GetMessageA
		TranslateMessage     dd rva _TranslateMessage
		DispatchMessageA     dd rva _DispatchMessageA  
		GetSystemMetrics     dd rva _GetSystemMetrics
		GetWindowTextA 	 	 dd rva _GetWindowTextA
		GetWindowTextLengthA dd rva _GetWindowTextLengthA
	dd 0
	
	user32_name 			  db 'user32.dll',0
		_MessageBoxA 		  db 0,0,'MessageBoxA',0
		_LoadIconA 			  db 0,0,'LoadIconA',0
		_LoadCursorA 	      db 0,0,'LoadCursorA',0
		_RegisterClassA 	  db 0,0,'RegisterClassA',0
		_CreateWindowExA 	  db 0,0,'CreateWindowExA',0
		_DefWindowProcA 	  db 0,0,'DefWindowProcA',0
		_PostQuitMessage 	  db 0,0,'PostQuitMessage',0
		_GetMessageA		  db 0,0,'GetMessageA',0
		_TranslateMessage 	  db 0,0,'TranslateMessage',0
		_DispatchMessageA 	  db 0,0,'DispatchMessageA',0
		_GetSystemMetrics	  db 0,0,'GetSystemMetrics',0
		_GetWindowTextA   	  db 0,0,'GetWindowTextA',0
		_GetWindowTextLengthA db 0,0,'GetWindowTextLengthA',0
	dd 0
