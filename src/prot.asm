.586 
.model flat,stdcall 
option casemap:none
assume fs:flat
include c:\masm32\include\windows.inc
include c:\masm32\include\user32.inc
include c:\masm32\include\kernel32.inc
include c:\masm32\include\comctl32.inc
include c:\masm32\include\comdlg32.inc
include c:\masm32\include\gdi32.inc 
include c:\masm32\include\shell32.inc
include aplib.inc
includelib c:\masm32\lib\kernel32.lib
includelib c:\masm32\lib\user32.lib
includelib c:\masm32\lib\comctl32.lib
includelib c:\masm32\lib\comdlg32.lib
includelib c:\masm32\lib\gdi32.lib 
includelib c:\masm32\lib\shell32.lib
includelib aplib.lib

include	data.asm

.CODE
include	shell.asm
start:
	invoke	GetModuleHandle, NULL
	mov	hInst,eax
	lea	esi,FontName
	lea	edi,LogFont.lfFaceName
	mov	ecx,10h
	rep	movsb
	mov	LogFont.lfHeight,0fffffff4h
	mov	LogFont.lfWeight,109h
	mov	LogFont.lfCharSet,1h
	invoke	DialogBoxParam, hInst, OFFSET MainDlgName,NULL,OFFSET DlgProc,NULL
	invoke	ExitProcess,0
;*******************主窗口********************************
DlgProc proc hWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
	MOV	eax,uMsg
	.if	eax == WM_CLOSE		;退出消息处理
		invoke	VirtualFree, MessageBufferAddr, 0, MEM_RELEASE
		.if	IsSaveSet == 1
			invoke	SaveTheSet
		.endif
		invoke	PostQuitMessage,NULL
	.elseif	eax == WM_INITDIALOG	;初试化消息处理
		invoke InitCommonControls
		invoke GetDlgItem,hWnd,IDC_TAB1
		MOV hwndTab,eax			
		MOV ItemStruct.imask,TCIF_TEXT
		MOV ItemStruct.lpReserved1,0
		MOV ItemStruct.lpReserved2,0
  		MOV ItemStruct.iImage,0
 		MOV ItemStruct.lParam,0
		MOV ItemStruct.pszText,OFFSET TabTitle1
		MOV ItemStruct.cchTextMax,sizeof TabTitle1
		invoke SendMessage,hwndTab,TCM_INSERTITEM,0,OFFSET ItemStruct
		MOV ItemStruct.pszText,OFFSET TabTitle2
		MOV ItemStruct.cchTextMax,sizeof TabTitle2
		invoke SendMessage,hwndTab,TCM_INSERTITEM,1,OFFSET ItemStruct
		MOV ItemStruct.pszText,OFFSET TabTitle3
		MOV ItemStruct.cchTextMax,sizeof TabTitle3
		invoke SendMessage,hwndTab,TCM_INSERTITEM,2,OFFSET ItemStruct
		invoke CreateDialogParam,hInst,OFFSET Child1Name,hwndTab,OFFSET ChildDlgProc1,0
		MOV Child1hWnd,eax
		invoke CreateDialogParam,hInst,OFFSET Child2Name,hwndTab,OFFSET ChildDlgProc2,0
		MOV Child2hWnd,eax
		invoke CreateDialogParam,hInst,OFFSET Child3Name,hwndTab,OFFSET ChildDlgProc3,0
		MOV Child3hWnd,eax
		MOV WhichTabChosen,0 				
		invoke ShowWindow,Child1hWnd,SW_SHOWDEFAULT
        .elseif	eax == WM_COMMAND
		MOV eax,wParam
        .elseif	eax == WM_NOTIFY
		MOV eax,lParam	
		MOV eax, (NMHDR PTR [eax]).code	
		.if eax == TCN_SELCHANGE
			MOV eax,WhichTabChosen
			.if	eax == 2
				mov	TextOutCY,0
			.endif
			MOV eax,[Handles+eax*4]
			invoke ShowWindow,eax,SW_HIDE
			invoke SendMessage,hwndTab,TCM_GETCURSEL,0,0												; Ok which one is BEING chosen right now?
			MOV WhichTabChosen,eax
			MOV eax,[Handles+eax*4]
 			invoke ShowWindow,eax,SW_SHOWDEFAULT
		.endif
	.else
		mov	eax,FALSE
		ret
	.endif		   
	mov	eax,TRUE
	ret
DlgProc endp
;***********************加密窗口*******************************
ChildDlgProc1  PROC ProthWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
	mov	eax,ProthWnd
	mov	hProtDlg,eax
	mov	eax,uMsg
	.if	eax == WM_INITDIALOG	;初试化消息处理
		;*****创建消息框缓冲
		invoke	VirtualAlloc, NULL, 1000h, MEM_COMMIT, PAGE_READWRITE	
		mov	MessageBufferAddr, eax
		;***取得选项、保护按钮句柄
		invoke	GetDlgItem, hProtDlg, IDC_PROT_BUTTON
		mov	hProtButton,eax
	.elseif	eax == WM_COMMAND
		mov	eax,wParam
		.if eax == IDC_OPEN_BUTTON	;是打开文件命令吗？
			invoke	RtlZeroMemory,MessageBufferAddr,1000h
			mov	DebugMsgSize,0
			invoke	RtlZeroMemory,OFFSET FileName,MAXSIZE	;清空文件名缓冲
			mov	Openfilename.lStructSize,SIZEOF Openfilename 
			push	ProthWnd 
			pop	Openfilename.hWndOwner
			push	hInst
			pop	Openfilename.hInstance 
			mov	Openfilename.lpstrFilter, OFFSET FilterString 
			mov	Openfilename.lpstrFile, OFFSET FileName 
			mov	Openfilename.nMaxFile,MAXSIZE 
			mov	Openfilename.Flags, OFN_FILEMUSTEXIST or \ 
				OFN_PATHMUSTEXIST or OFN_LONGNAMES or\ 
				OFN_EXPLORER or OFN_HIDEREADONLY 
			invoke	GetOpenFileName, ADDR Openfilename
				.IF eax==TRUE		;文件打开成功
					invoke	SetDlgItemText,ProthWnd,IDC_FILE_EDIT,ADDR FileName
					invoke	FileIsExe	;是合法的PE-EXE文件吗？
					.if	eax==1
						invoke	EnableWindow, hProtButton, TRUE
					.else
						invoke	EnableWindow, hProtButton, FALSE
					.endif
				.ENDIF
		.elseif eax == IDC_PROT_BUTTON		;是保护命令吗？
			pushad
			invoke	EnableWindow, hProtButton, FALSE
			invoke	ProtTheFile
			popad
		.endif
	.else
		mov	eax,FALSE
		ret
	.endif		   
	mov	eax,TRUE
	ret
ChildDlgProc1	ENDP
;*******************选项窗口************************
ChildDlgProc2  PROC OptionhWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
	mov	eax,uMsg
	.if	eax == WM_INITDIALOG	;选项对话框初始化
		invoke	GetPrivateProfileInt,addr IniSectionName,addr I_issaveset,0h,addr IniFileName
		.if	eax == 1
			mov	IsSaveSet,1
			invoke	CheckDlgButton,OptionhWnd,IDC_SAVESET,BST_CHECKED
		.endif
		invoke	GetPrivateProfileInt,addr IniSectionName,addr I_iscreatebak,0h,addr IniFileName
		.if	eax == 1
			mov	IsCreateBak,1
			invoke	CheckDlgButton,OptionhWnd,IDC_CREATEBAK,BST_CHECKED
		.endif
		invoke	GetPrivateProfileInt,addr IniSectionName,addr I_Ispackres,0h,addr IniFileName
		.if	eax == 1
			mov	IsPackRes,1
			invoke	CheckDlgButton,OptionhWnd,IDC_PACKRES,BST_CHECKED
		.endif
		invoke	GetPrivateProfileInt,addr IniSectionName,addr I_Issavesdata,0h,addr IniFileName
		.if	eax == 1
			mov	IsSaveSData,1
			invoke	CheckDlgButton,OptionhWnd,IDC_SDATA,BST_CHECKED
		.endif
		invoke	GetPrivateProfileInt,addr IniSectionName,addr I_Iscodeprot,1h,addr IniFileName
		.if	eax == 1
			mov	IsCodeProt,1
			invoke	CheckDlgButton,OptionhWnd,IDC_CODEPROT,BST_CHECKED
		.endif
		invoke	GetPrivateProfileInt,addr IniSectionName,addr I_Clssecname,1h,addr IniFileName
		.if	eax == 1
			mov	IsClsSecName,1
			invoke	CheckDlgButton,OptionhWnd,IDC_CLSSECNAME,BST_CHECKED
		.endif
		invoke	GetPrivateProfileInt,addr IniSectionName,addr I_Ismergesection,1h,addr IniFileName
		.if	eax == 1
			mov	IsMergeSection,1
			invoke	CheckDlgButton,OptionhWnd,IDC_MERGESECTION,BST_CHECKED
		.endif
		invoke	GetPrivateProfileInt,addr IniSectionName,addr I_Isprotimptable,1h,addr IniFileName
		.if	eax == 1
			mov	IsProtImpTable,1
			invoke	CheckDlgButton,OptionhWnd,IDC_APIPROT,BST_CHECKED
		.endif
		invoke	GetPrivateProfileInt,addr IniSectionName,addr I_IsReFileHead,1h,addr IniFileName
		.if	eax == 1
			mov	IsReFileHead,1
			invoke	CheckDlgButton,OptionhWnd,IDC_REFILEHEAD,BST_CHECKED
		.endif
		invoke	GetPrivateProfileInt,addr IniSectionName,addr I_IsFileAlignment200,1h,addr IniFileName
		.if	eax == 1
			mov	IsFileAlignment200,1
			invoke	CheckDlgButton,OptionhWnd,IDC_FA200,BST_CHECKED
		.endif
		invoke	GetPrivateProfileInt,addr IniSectionName,addr I_IsNoRelocation,1h,addr IniFileName
		.if	eax == 1
			mov	IsNoRelocation,1
			invoke	CheckDlgButton,OptionhWnd,IDC_NOREL0,BST_CHECKED
		.endif
	.elseif	eax == WM_COMMAND
		mov	eax,wParam
		.if	eax == IDC_OPTIONOK
			;*******创建备份吗？
			invoke	SendDlgItemMessage, OptionhWnd, IDC_CREATEBAK, BM_GETCHECK, 0, 0
			.if	eax == BST_CHECKED
				mov	IsCreateBak,1
			.else
				mov	IsCreateBak,0
			.endif
			;*******清空段名吗？
			invoke	SendDlgItemMessage, OptionhWnd, IDC_CLSSECNAME, BM_GETCHECK, 0, 0
			.if	eax == BST_CHECKED
				mov	IsClsSecName,1
			.else
				mov	IsClsSecName,0
			.endif
			;*******合并区段吗？
			invoke	SendDlgItemMessage, OptionhWnd, IDC_MERGESECTION, BM_GETCHECK, 0, 0
			.if	eax == BST_CHECKED
				mov	IsMergeSection,1
			.else
				mov	IsMergeSection,0
			.endif
			;********压缩资源吗?
			invoke	SendDlgItemMessage, OptionhWnd, IDC_PACKRES, BM_GETCHECK, 0, 0
			.if	eax == BST_CHECKED
				mov	IsPackRes,1
			.else
				mov	IsPackRes,0
			.endif
			;********保留额外数据吗?
			invoke	SendDlgItemMessage, OptionhWnd, IDC_SDATA, BM_GETCHECK, 0, 0
			.if	eax == BST_CHECKED
				mov	IsSaveSData,1
			.else
				mov	IsSaveSData,0
			.endif
			;*******输入表加密吗?
			invoke	SendDlgItemMessage, OptionhWnd, IDC_APIPROT, BM_GETCHECK, 0, 0
			.if	eax == BST_CHECKED
				mov	IsProtImpTable,1
			.else
				mov	IsProtImpTable,0
			.endif
			;*******重算文件头大小吗?
			invoke	SendDlgItemMessage, OptionhWnd, IDC_REFILEHEAD, BM_GETCHECK, 0, 0
			.if	eax == BST_CHECKED
				mov	IsReFileHead,1
			.else
				mov	IsReFileHead,0
			.endif
			;*******强制文件对齐为200吗?
			invoke	SendDlgItemMessage, OptionhWnd, IDC_FA200, BM_GETCHECK, 0, 0
			.if	eax == BST_CHECKED
				mov	IsFileAlignment200,1
			.else
				mov	IsFileAlignment200,0
			.endif
			;*******去处重定位数据吗?
			invoke	SendDlgItemMessage, OptionhWnd, IDC_NOREL0, BM_GETCHECK, 0, 0
			.if	eax == BST_CHECKED
				mov	IsNoRelocation,1
			.else
				mov	IsNoRelocation,0
			.endif

			;********特殊代码加密吗?
			invoke	SendDlgItemMessage, OptionhWnd, IDC_CODEPROT, BM_GETCHECK, 0, 0
			.if	eax == BST_CHECKED
				mov	IsCodeProt,1
			.else
				mov	IsCodeProt,0
			.endif
			;********保存设置吗?
			invoke	SendDlgItemMessage, OptionhWnd, IDC_SAVESET, BM_GETCHECK, 0, 0
			.if	eax == BST_CHECKED
				mov	IsSaveSet,1
			.else
				mov	IsSaveSet,0
			.endif

		.endif
	.else
		mov	eax,FALSE
		ret
	.endif
      	mov     eax,TRUE       
	ret           
ChildDlgProc2	ENDP
;*******************关于窗口******************************
ChildDlgProc3  PROC AbouthWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
LOCAL	hMBitMapDc:HDC
LOCAL	hMBitMap:dword
LOCAL	ps:PAINTSTRUCT
LOCAL	rect:RECT
LOCAL	TextSizeCX:dword
LOCAL	TextSizeCY:dword
	MOV eax,uMsg
	.if	eax == WM_PAINT
		invoke	BeginPaint,AbouthWnd,addr ps
		mov	hDc,eax
		invoke	BitBlt,hMDc,0h,0h,115h,50h,hMDc3,0,0,0cc0020h
		invoke	BitBlt,hDc,9h,8h,115h,91h,hMDc,0,0,0cc0020h
		invoke	EndPaint,AbouthWnd,addr ps
	.elseif	eax == WM_INITDIALOG
		invoke	SetTimer,AbouthWnd,200h,46h,NULL
		invoke	GetDC,AbouthWnd
		mov	hDc,eax
		;*******创建一个全黑的内存设备用来最后输出
		invoke	CreateCompatibleDC,hDc
		mov	hMDc,eax
		invoke	CreateCompatibleBitmap,hDc,200h,200h
		mov	hMBitMapDc,eax
		invoke	SelectObject,hMDc,hMBitMapDc
		mov	hMBitMap,EAX
		invoke	CreateSolidBrush, 0h
		mov	hBrush,eax
		mov	rect.top,0h
		mov	rect.left,0h
		mov	rect.right,115h
		mov	rect.bottom,210h
		invoke	FillRect,hMDc,addr rect,hBrush
		;*******创建一个带文字的内存设备
		invoke	CreateCompatibleDC,hDc
		mov	hMDc2,eax
		invoke	SetTextColor,hMDc2,0ff7070h
		invoke	SetBkMode,hMDc2,TRANSPARENT
		invoke	CreateFontIndirect,addr LogFont
		invoke	SelectObject,hMDc2,eax
		invoke	CreateCompatibleBitmap,hDc,200h,200h
		invoke	SelectObject,hMDc2,eax
		invoke	FillRect,hMDc2,addr rect,hBrush
		mov	TextOutX,40h
		mov	TextOutY,50h
		mov	esi,OFFSET AboutText
		mov	al,byte ptr [esi]
		.while	al
			.if	al == 0dh
				add	TextOutY,10h
				add	esi,2h
				mov	TextOutX,40h
			.else
				invoke	GetTextExtentPoint32,hMDc2,esi,1,addr TextSizeCX
				invoke	TextOut,hMDc2,TextOutX,TextOutY,esi,1h
				mov	eax,TextSizeCX
				add	TextOutX,eax
				inc	esi
			.endif
			mov	al,byte ptr [esi]
		.endw
		;*******创建一个带图片的内存设备
		invoke	CreateCompatibleDC,hDc
		mov	hMDc3,eax
		invoke	LoadBitmap,hInst,IDB_BITMAP 
		mov	hBitMap,eax
		invoke	SelectObject,hMDc3,hBitMap
		;*******创建一个带图标图片的内存设备,然后释放
		invoke	CreateCompatibleDC,hDc
		mov	esi,eax
		invoke	LoadBitmap,hInst,IDB_BITMAP2 
		invoke	SelectObject,esi,eax
		invoke	BitBlt,hMDc2,80h,120h,20h,20h,esi,0,0,0cc0020h
		invoke	ReleaseDC,AbouthWnd,esi
		;*******
		invoke	BitBlt,hMDc,0h,0h,115h,50h,hMDc3,0,0,0cc0020h
		invoke	ReleaseDC,AbouthWnd,hDc
	.elseif	eax == WM_TIMER
		invoke	GetDC,AbouthWnd
		mov	hDc,eax
		invoke	BitBlt,hMDc,0h,55h,115h,34h,hMDc2,0,TextOutCY,0cc0020h
		inc	TextOutCY
		.if	TextOutCY == 140h
			mov	TextOutCY,0
		.endif
		invoke	BitBlt,hDc,9h,8h,115h,91h,hMDc,0,0,0cc0020h		
		invoke	ReleaseDC,AbouthWnd,hDc
	.elseif	eax == WM_COMMAND
		mov	eax,wParam
		.if eax == IDC_CCGSITE	;是连接CCG站点吗？
			invoke	ShellExecute, SW_SHOWMAXIMIZED, NULL, ADDR CcgSiteIp, NULL, NULL,NULL
		.endif
	.else
		mov	eax,FALSE
		ret
	.endif
      	mov     eax,TRUE       
	ret
ChildDlgProc3	ENDP
;*******************文件是有效的PE-EXE文件吗?*******************************
FileIsExe	PROC
  LOCAL ReadBuffer	:DWORD
  LOCAL NumberOfBytesRW	:DWORD
	push	esi
	invoke	AddLine,ADDR FileName
	invoke	CreateFile,ADDR FileName, GENERIC_READ+GENERIC_WRITE, FILE_SHARE_READ+FILE_SHARE_WRITE,0, 3, FILE_ATTRIBUTE_NORMAL,NULL
	cmp	eax,INVALID_HANDLE_VALUE
	jz	OpenFileErr
	mov	hFile,eax
	;**********文件头是“MZ”吗？
	mov	ReadBuffer,0
	invoke  SetFilePointer, hFile, 0h, NULL,  FILE_BEGIN
	invoke  ReadFile, hFile, ADDR ReadBuffer, 4, ADDR NumberOfBytesRW, NULL
	mov	eax,ReadBuffer
	cmp	ax,'ZM'
	jnz	FileIsNotExe
	;****************************
	mov	ReadBuffer,0
	invoke  SetFilePointer, hFile, 3ch, NULL,  FILE_BEGIN
	invoke  ReadFile, hFile, ADDR ReadBuffer, 4, ADDR NumberOfBytesRW, NULL
	mov	eax,ReadBuffer
	mov	esi,eax
	;*************是PE文件吗？
	mov	ReadBuffer,0
	invoke  SetFilePointer, hFile, esi, NULL,  FILE_BEGIN
	invoke  ReadFile, hFile, ADDR ReadBuffer, 2, ADDR NumberOfBytesRW, NULL
	cmp	ReadBuffer,'EP'
	jnz	FileIsNotPe
	;*************是EXE文件还是DLL文件
	mov	eax,esi
	add	eax,16h
	mov	ReadBuffer,0
	invoke  SetFilePointer, hFile, eax, NULL,  FILE_BEGIN
	invoke  ReadFile, hFile, ADDR ReadBuffer, 2, ADDR NumberOfBytesRW, NULL
	mov	eax,ReadBuffer
	test	ax,2000h
	jnz	FileMaybeDll
	invoke	AddLine,ADDR M_FileIsPeExe
	invoke	CloseHandle,hFile
	pop	esi
	xor	eax,eax
	inc	eax
	ret
    OpenFileErr:
	invoke	AddLine,ADDR M_FileOpenErr
	pop	esi
	xor	eax,eax
	ret
    FileIsNotExe:
	invoke	AddLine,ADDR M_FileIsNotExe
	pop	esi
	xor	eax,eax
	ret
    FileIsNotPe:
	invoke	AddLine,ADDR M_FileIsNotPe
	pop	esi
	xor	eax,eax
	ret
    FileMaybeDll:
	invoke	AddLine,ADDR M_FileMaybeDll
	pop	esi
	xor	eax,eax
	ret
FileIsExe	ENDP
;*************************压缩保护文件****************************
ProtTheFile	PROC
  LOCAL ReadBuffer	:DWORD
  LOCAL NumberOfBytesRW	:DWORD
	pushad
	.if	IsCreateBak==1h
		invoke	CreateBakFile,ADDR FileName
		.if	eax!=0
			invoke	AddLine,ADDR M_MakeBakRight
		.else
			invoke	AddLine,ADDR M_MakeBakWrong
		.endif
	.endif
  	invoke	CreateFile,ADDR FileName, GENERIC_READ+GENERIC_WRITE, FILE_SHARE_READ+FILE_SHARE_WRITE,0, 3, FILE_ATTRIBUTE_NORMAL,NULL
	cmp	eax,INVALID_HANDLE_VALUE
	jz	OpenFileErr2
	mov	hFile,eax
	mov	ReadBuffer,0
	invoke  SetFilePointer, hFile, 3ch, NULL,  FILE_BEGIN
	invoke  ReadFile, hFile, ADDR ReadBuffer, 4, ADDR NumberOfBytesRW, NULL
	mov	eax,ReadBuffer
	mov	esi,eax
	;**********取文件映象大小,申请内存
	add	eax,50h
	invoke  SetFilePointer, hFile, eax, NULL,  FILE_BEGIN
	invoke  ReadFile, hFile, ADDR PeImageSize, 4, ADDR NumberOfBytesRW, NULL

	invoke	VirtualAlloc, NULL, PeImageSize, MEM_COMMIT, PAGE_READWRITE
	test	eax,eax
	jz	VirtualAllocErr
	mov	MapOfFile, eax
	;**********取PE头大小,读入PE头
	mov	eax,esi
	add	eax,54h
	invoke  SetFilePointer, hFile, eax, NULL,  FILE_BEGIN
	invoke  ReadFile, hFile, ADDR ReadBuffer, 4, ADDR NumberOfBytesRW, NULL
	invoke  SetFilePointer, hFile, 0, NULL,  FILE_BEGIN
	invoke  ReadFile, hFile, MapOfFile, ReadBuffer, ADDR NumberOfBytesRW, NULL
	;**************
	mov	eax,MapOfFile
	add	eax,esi
	mov	PeHeadBase,eax
	;**********取PE文件的一些信息
	mov	edi,PeHeadBase
	assume	edi : ptr IMAGE_NT_HEADERS
	mov	eax,dword ptr [edi].OptionalHeader.ImageBase
	mov	PeImageBase,eax
	;**********读入各个区块,并对区块资料取整****
	mov	edi,PeHeadBase
	assume	edi : ptr IMAGE_NT_HEADERS
	mov	eax,dword ptr [edi].OptionalHeader.FileAlignment
	mov	FileAlignment,eax
	.if	IsFileAlignment200 == 1
		mov	FileAlignment,200h
		mov	dword ptr [edi].OptionalHeader.FileAlignment,200h
	.endif
	mov	eax,dword ptr [edi].OptionalHeader.SectionAlignment
	mov	SectionAlignment,eax
	movzx	ecx,word ptr [edi].FileHeader.NumberOfSections
	movzx	esi,word ptr [edi].FileHeader.SizeOfOptionalHeader
	add	esi,edi
	add	esi,18h
	mov	SecTableBase,esi
    LoadSections:
	push	ecx
	mov	eax,dword ptr [esi+14h]		;区块文件偏移
	invoke  SetFilePointer, hFile, eax, NULL,  FILE_BEGIN
	mov	ecx,dword ptr [esi+0ch]		;区块映象偏移
	add	ecx,MapOfFile
	mov	ebx,dword ptr [esi+10h]		;区块文件大小
	invoke	ReadFile, hFile, ecx, ebx, ADDR NumberOfBytesRW, NULL
	mov	ebx,dword ptr [esi+08h]		;区块映象大小
	invoke	GetIntegral,ebx,SectionAlignment
	mov	dword ptr [esi+08h],eax
	add	esi,28h
	pop	ecx
	loop	LoadSections
	invoke	AddLine,ADDR M_ReadFileOK
	invoke	GetIntegral,PeImageSize,SectionAlignment
	mov	PeImageSize,eax
	mov	dword ptr [edi].OptionalHeader.SizeOfImage,eax
	;************保留额外数据吗?
	mov	eax,IsSaveSData
	.if	eax == 1
		invoke	GetFileSize, hFile, 0
		sub	esi,28h
		sub	eax,dword ptr [esi+14h]
		sub	eax,dword ptr [esi+10h]
		.if	eax != 0
			cdq
			.if	edx == 0
				mov	edi,eax
				invoke	VirtualAlloc, NULL, edi, MEM_COMMIT, PAGE_READWRITE
				mov	MapOfSData,eax
				invoke	ReadFile, hFile, MapOfSData, edi, ADDR NumberOfBytesRW, NULL
				mov	eax,NumberOfBytesRW
				mov	MapOfSDataUsed,eax
				invoke	AddLine,ADDR M_SaveSDataOK
			.else
				invoke	AddLine,ADDR M_HaveNoSData
			.endif
		.else
			invoke	AddLine,ADDR M_HaveNoSData
		.endif
	.endif
	invoke	CloseHandle,hFile
	;***********去处重定位数据*********
	.if	IsNoRelocation == 1
		invoke	ClsRelocation
	.endif
	;***********特殊代码加密***********
	.if	IsCodeProt==1
		invoke	VirtualAlloc, NULL, 5000h, MEM_COMMIT, PAGE_READWRITE
		.if	eax==0
			jmp	VirtualAllocErr
		.endif
		mov	MapOfCodeProt,eax
		invoke	ProtCode
		add	eax,8h
		mov	MapOfCodeProtUsed,eax	;最后加一段空白,以示结束
		invoke	AddLine,ADDR M_CodeProtIsOver
	.endif
	;************输入表加密***********
	.if	IsProtImpTable==1
		invoke	VirtualAlloc, NULL, 0a000h, MEM_COMMIT, PAGE_READWRITE
		.if	eax==0
			jmp	VirtualAllocErr
		.endif
		mov	MapOfImpProt,eax
		invoke	MoveImpTable
		mov	MapOfImpProtUsed,eax
		invoke	ClsImpTable
		invoke	AddLine,ADDR M_ImpTableProtIsOver
	.endif
	;***********压缩资源******************
	.if	IsPackRes ==1
		invoke	FindFirstResADDR
		mov	FirstResADDR,eax		;最前面的资源的存放偏移
		invoke	VirtualAlloc, NULL, 5000h, MEM_COMMIT, PAGE_READWRITE
		.if	eax==0
			jmp	VirtualAllocErr
		.endif
		mov	MapOfPackRes,eax
		mov	MapOfPackResUsed,0h
		invoke	MoveRes,3h,MapOfPackRes,MapOfPackResUsed
		mov	MapOfPackResUsed,eax
		invoke	MoveRes,0eh,MapOfPackRes,MapOfPackResUsed
		mov	MapOfPackResUsed,eax
		invoke	MoveRes,10h,MapOfPackRes,MapOfPackResUsed
		mov	MapOfPackResUsed,eax
		invoke	AddLine,ADDR M_PackResIsOver
	.endif
	;***********合并区段**********
	.if	IsMergeSection ==1
		invoke	MergeSection
		invoke	AddLine,ADDR M_MergeSectionIsOver
	.endif
	;***********压缩***************
	invoke	VirtualAlloc, NULL, 100000h, MEM_COMMIT, PAGE_READWRITE
	.if	eax==0
		jmp	VirtualAllocErr
	.endif
	mov	lpPackBuffer,eax
	invoke	CreateFile,ADDR FileName, GENERIC_READ+GENERIC_WRITE, FILE_SHARE_READ+FILE_SHARE_WRITE,0,CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,NULL
	mov	hFile,eax
		;因为还要压缩写入外壳部分和重写文件头,所以上面两个函数不放在PackFile里
	invoke	PackFile
	;*************处理外壳并写入******
	invoke	VirtualAlloc, NULL, 20000h, MEM_COMMIT, PAGE_READWRITE
	.if	eax==0
		jmp	VirtualAllocErr
	.endif
	mov	MapOfShell,eax
	invoke	DisposeShell
	mov	MapOfShellUsed,eax
	push	eax
	mov	ebx,esp
	invoke	WriteFile, hFile,MapOfShell ,MapOfShellUsed,ebx, NULL
	add	esp,4h
	;*******清空段名吗?*****************
	.if	IsClsSecName == 1
		invoke	ClsSectionName
	.endif
	;***********重写文件头**************
	invoke  SetFilePointer, hFile, 0h, NULL,  FILE_BEGIN
	mov	esi,PeHeadBase
	assume	esi : ptr IMAGE_NT_HEADERS
	mov	ebx,PeHeadSize
	invoke	WriteFile, hFile,MapOfFile ,ebx,ADDR NumberOfBytesRW, NULL
	;***********写入额外代码************
	invoke  SetFilePointer, hFile, 0h, NULL,  FILE_END
	invoke	WriteFile, hFile,MapOfSData,MapOfSDataUsed,ADDR NumberOfBytesRW, NULL
	;***********加密完成,清理***********
	invoke	CloseHandle,hFile
	invoke	VirtualFree, lpPackBuffer, 0, MEM_RELEASE	;释放压缩缓冲
	invoke	VirtualFree, MapOfFile, 0, MEM_RELEASE
	.if	MapOfCodeProt != 0
		invoke	VirtualFree, MapOfCodeProt, 0, MEM_RELEASE
	.endif
	.if	MapOfImpProt != 0
		invoke	VirtualFree, MapOfImpProt, 0, MEM_RELEASE
	.endif
	.if	MapOfPackRes != 0
		invoke	VirtualFree, MapOfPackRes, 0, MEM_RELEASE
	.endif
	.if	MapOfSData != 0
		invoke	VirtualFree, MapOfSData, 0, MEM_RELEASE
	.endif
	lea	edi,hFile
	mov	ecx,FileDataEnd-hFile
	xor	eax,eax
	rep	stosb
	popad
	ret
    OpenFileErr2:
	invoke	AddLine,ADDR M_FileOpenErr
	popad
	xor	eax,eax
	ret
    VirtualAllocErr:
	invoke	AddLine,ADDR M_VirtualAllocErr
	popad
	xor	eax,eax
	ret
ProtTheFile	ENDP
;*****************创建备份文件*******************************
CreateBakFile	PROC	SourceFileNameADDR:DWORD
;将SourceFileNameADDR指向的字符串的文件创建一个加后缀'BAK'的备份文件
;返回eax的值表示创建成功与否.
  LOCAL	BakFileNameADDR:DWORD
	push	edi
	push	esi
	invoke	VirtualAlloc, NULL, 1000h, MEM_COMMIT, PAGE_READWRITE
	mov	BakFileNameADDR,eax
	mov	edi,eax
	mov	esi,SourceFileNameADDR
	invoke	MoveString,esi,edi
	add	edi,eax
	mov	dword ptr [edi],'kab.'	;于原文件名加后缀.bak
	invoke	CopyFile, SourceFileNameADDR , BakFileNameADDR ,0
	push	eax
	invoke	VirtualFree, BakFileNameADDR, 0, MEM_RELEASE
	pop	eax
	pop	esi
	pop	edi
	ret
CreateBakFile	endp
;***************特殊代码加密部分*****************************
ProtCode	PROC
;将调用原输入表的CALL [????]和JMP [????]统一改为CALL ????,
;????指向外壳申请的地址空间的一段代码,由这段代码根据CALL的返回
;地址与原地址记录相比较后找出真正该使用的输入表项,再指向它运行
;加密后的数据结构为"  返回地址:DWORD,原输入表项地址:DWORD  "
;为了区别原来的CALL [????]和JMP [????],将原来CALL [????]的返回
;地址的最高位置1作为标记.
  LOCAL	CodeSectionBase:DWORD
  LOCAL	CodeSectionSize:DWORD
  LOCAL	CodeProtSize:DWORD
	mov	CodeProtSize,0
	mov	CodeSectionSize,0
	mov	CodeSectionBase,0
	mov	edi,PeHeadBase
	assume	edi : ptr IMAGE_NT_HEADERS
	;*********取代码段参数**
	mov	eax,SecTableBase
	mov	ebx,dword ptr [eax+8h]
	mov	CodeSectionSize,ebx
	mov	ebx,dword ptr [eax+0ch]
	add	ebx,MapOfFile
	mov	CodeSectionBase,ebx
	;*********取输入表地址***
	mov	edi,dword ptr [edi].OptionalHeader.DataDirectory[SIZEOF IMAGE_DATA_DIRECTORY].VirtualAddress
	add	edi,MapOfFile
	;************************
    ProtNextDllCode:
	mov	eax,dword ptr [edi+0ch]
	.if	eax != 0
		mov	esi,dword ptr [edi+10h]
	    ProtNextFuncCode:
		mov	edx,esi
		add	edx,PeImageBase		;call [edx] or Jmp [edx]
		;***********
		mov	eax,esi
		add	eax,MapOfFile
		mov	eax,dword ptr [eax]
		;**********
		.if	eax!=0
			push	esi
			mov	esi,CodeSectionBase	;查找起点
			mov	ecx,CodeSectionSize	
			sub	ecx,3h			;查找范围
		    SearchNextCall:
			mov	eax,dword ptr [esi]
			.if	eax == edx
				push	edi
				mov	edi,MapOfCodeProt
				add	edi,CodeProtSize
				lea	eax,[esi+4h]	
				sub	eax,MapOfFile
				add	eax,PeImageBase
				push	eax				;加密后CALL的返回地址
				mov	ax,word ptr [esi-2]
				.if	ax == 15ffh	
					pop	eax
					mov	dword ptr [edi],eax
					mov	dword ptr [edi+4h],edx
					mov	word ptr [esi-2h],0e890h
					mov	dword ptr [esi],0h	;将原来的CALL [XXXX]和
					add	CodeProtSize,8h		;JMP [XXXX]统一改为:
				.elseif	ax == 25ffh			;NOP
					pop	eax			;CALL XXXX
					or	eax,80000000h		;原来jmp [xxxx]做一标记
					mov	dword ptr [edi],eax
					mov	dword ptr [edi+4h],edx
					mov	word ptr [esi-2h],0e890h
					mov	dword ptr [esi],0h
					add	CodeProtSize,8h
				.else	
					pop	eax
				.endif
				pop	edi
			.endif
			inc	esi
			loop	SearchNextCall
			pop	esi
		.else
			jmp	AllFuncCodeIsProt
		.endif
		add	esi,4h
		jmp	ProtNextFuncCode
	    AllFuncCodeIsProt:
	.else
		jmp	AllDllCodeProt
	.endif
	add	edi,14h
	jmp	ProtNextDllCode
    AllDllCodeProt:
	mov	eax,CodeProtSize
	ret
ProtCode	endp
;***************输入表加密部分************************
MoveImpTable	PROC
;将一个程序的输入表的所有换种结构方式存储,以达到加密的目的.
;返回eax的值为加密生成数据的大小.
	mov	edx,PeHeadBase
	assume	edx : ptr IMAGE_NT_HEADERS
	mov	edx,dword ptr [edx].OptionalHeader.DataDirectory[SIZEOF IMAGE_DATA_DIRECTORY].VirtualAddress
	add	edx,MapOfFile		;输入表地址
	mov	edi,MapOfImpProt
	mov	eax,dword ptr [edx+10h]
	.while	eax!=0
		mov	dword ptr [edi],eax
		add	edi,4h
		inc	edi		;空一个字节,放后面dllname字符串的长度
		mov	esi,dword ptr [edx+0ch]
		add	esi,MapOfFile
		invoke	MoveString,esi,edi
		mov	byte ptr [edi-1],al
		add	edi,eax
		inc	edi		;空一字节,作为字符串结束标记
		mov	ecx,edi		;[ecx]存放后续函数的数量
		add	edi,4h	
		mov	esi,dword ptr [edx]
		.if	esi == 0
			mov	esi,dword ptr [edx+10h]
		.endif
		add	esi,MapOfFile
		mov	eax,dword ptr [esi]
		.while	eax
			push	edx
			cdq
			.if	edx == 0
				add	eax,MapOfFile
				add	eax,2h
				inc	edi
				invoke	MoveString,eax,edi
				mov	byte ptr [edi-1],al
				add	edi,eax
				inc	edi		;空一字节,作为字符串结束标记
			.else
				inc	edi
				and	eax,7fffffffh
				mov	dword ptr [edi],eax
				add	edi,5h
			.endif
			pop	edx
			inc	dword ptr [ecx]
			add	esi,4h
			mov	eax,dword ptr [esi]
		.endw
		add	edx,14h
		mov	eax,dword ptr [edx+10h]
	.endw
	sub	edi,MapOfImpProt
	add	edi,4h
	mov	eax,edi
	ret
MoveImpTable	endp
;***************清除原输入表************************
ClsImpTable	PROC
	pushad
	mov	edi,PeHeadBase
	assume	edi : ptr IMAGE_NT_HEADERS
	mov	edi,dword ptr [edi].OptionalHeader.DataDirectory[SIZEOF IMAGE_DATA_DIRECTORY].VirtualAddress
	add	edi,MapOfFile		;输入表地址
	mov	eax,dword ptr [edi+0ch]
	.while	eax!=0
		add	eax,MapOfFile
		invoke	ClsString,eax
		mov	esi,dword ptr [edi]
		.if	esi == 0
			mov	esi,dword ptr [edi+10h]
		.endif
		add	esi,MapOfFile
		xor	ecx,ecx
		mov	eax,dword ptr [esi]
		.while	eax !=0
			cdq
			.if	edx == 0
				add	eax,MapOfFile
				mov	word ptr [eax],0h
				add	eax,2h
				invoke	ClsString,eax
			.endif
			inc	ecx
			mov	dword ptr [esi],0h
			add	esi,4h
			mov	eax,dword ptr [esi]
		.endw
		xor	eax,eax
		push	edi
		mov	edi,dword ptr [edi+10h]
		add	edi,MapOfFile
		rep	stosd
		pop	edi
		mov	ecx,14h
		rep	stosb
		mov	eax,dword ptr [edi+0ch]
	.endw
	popad
	ret
ClsImpTable	endp
;****************压缩资源****************************
MoveRes		PROC	ResType:DWORD,MoveADDR:DWORD,MoveResSize:DWORD
  LOCAL	ResBase:DWORD
	pushad
	mov	edx,PeHeadBase
	assume	edx : ptr IMAGE_NT_HEADERS
	mov	edx,dword ptr [edx].OptionalHeader.DataDirectory[2*SIZEOF IMAGE_DATA_DIRECTORY].VirtualAddress
	add	edx,MapOfFile		;资源地址
	mov	ResBase,edx
	xor	ecx,ecx
	mov	cx,word ptr [edx+0ch]
	add	cx,word ptr [edx+0eh]
	add	edx,10h
    FindResDir:
	mov	eax,dword ptr [edx]
	.if	eax==ResType
		jmp	FoundResDir
	.elseif
		add	edx,8h
	.endif
	loop	FindResDir
	jmp	NotFoundResDir
    FoundResDir:
	mov	edx,dword ptr [edx+4h]
	and	edx,7fffffffh
	add	edx,ResBase
	xor	ecx,ecx
	mov	cx,word ptr [edx+0ch]
	add	cx,word ptr [edx+0eh]
	add	edx,10h
    MoveResItem:
	mov	ebx,dword ptr [edx+4h]
	and	ebx,7fffffffh
	add	ebx,ResBase
	add	ebx,10h
	mov	ebx,dword ptr [ebx+4h]
	add	ebx,ResBase
	push	ecx
	mov	ecx,dword ptr [ebx+4h]
	mov	esi,dword ptr [ebx]
	add	esi,MapOfFile
	mov	eax,PeImageSize
	add	eax,ShellEnd0-ShellStart0
	add	eax,MoveResSize
	mov	dword ptr [ebx],eax
	mov	edi,MoveADDR
	add	edi,MoveResSize
	add	MoveResSize,ecx
	push	esi
	push	ecx
	rep	movsb
	pop	ecx
	pop	edi
	xor	eax,eax
	rep	stosb
	pop	ecx
	add	edx,8h
	loop	MoveResItem
    NotFoundResDir:
	popad
	mov	eax,MoveResSize
	ret
MoveRes		endp
;*******************合并区段************************
MergeSection	PROC
;将开始的一些可以压缩的区段合并,可以缩小一些压缩后文件的大小
;经过此函数后融合生成的区段只有映象大小和映象偏移有用,文件大
;小和文件偏移在压缩回写时修正.
  LOCAL	NumOfSec :word
	pushad
	mov	ebx,PeHeadBase
	assume	ebx : ptr IMAGE_NT_HEADERS
	movzx	ecx,word ptr [ebx].FileHeader.NumberOfSections
	mov	NumOfSec,cx
	mov	edi,SecTableBase	;块表起点
	mov	esi,edi
	add	esi,28h
	dec	ecx
    MergeNextSection:
	cmp	dword ptr [esi], 'ade.'
	jz	MergeSectionOver
	cmp	dword ptr [esi], 'rsr.'
	jz	MergeSectionOver
	cmp	dword ptr [esi], 'oci.'
	jz	MergeSectionOver
	mov	eax,dword ptr [esi+8h]
	add	dword ptr [edi+8h],eax
	add	esi,28h
	loop	MergeNextSection
    MergeSectionOver:
	mov	eax,ecx
	inc	eax
	mov	word ptr [ebx].FileHeader.NumberOfSections,ax
	mov	eax,28h
	xor	edx,edx
	mul	ecx
	mov	ecx,eax		;剩余区块表的长度
	add	edi,28h
	rep	movsb
	movzx	ecx,NumOfSec
	sub	cx,word ptr [ebx].FileHeader.NumberOfSections
	mov	eax,28h
	xor	edx,edx
	mul	ecx
	mov	ecx,eax		;多余区块表的长度
	xor	eax,eax
	rep	stosb
	popad
	ret
MergeSection	endp
;****************压缩文件***************************
PackFile	PROC
  LOCAL	MEM		:DWORD
  LOCAL	MEMSize		:DWORD
  LOCAL	NumberOfBytesRW	:DWORD
  LOCAL	ResBase:DWORD
	pushad
	invoke	AddLine,ADDR M_BeginPackFile
	mov	CurrentSize,0
	mov	esi,PeHeadBase
	assume	esi : ptr IMAGE_NT_HEADERS
	mov	eax,dword ptr [esi].OptionalHeader.DataDirectory[2*SIZEOF IMAGE_DATA_DIRECTORY].VirtualAddress
	mov	ResBase,eax
	mov	edi,SecTableBase	;块表起点
	.if	IsReFileHead == 1
		movzx	eax,word ptr [esi].FileHeader.NumberOfSections
		inc	eax
		mov	ebx,28h
		xor	edx,edx
		mul	ebx
		mov	ebx,SecTableBase
		sub	ebx,MapOfFile
		add	ebx,eax
		invoke	GetIntegral,ebx,FileAlignment
		mov	ebx,eax
	.else
		mov	ebx,dword ptr [edi+14h]		;第一个区块文件偏移,即文件头大小
	.endif
	mov	PeHeadSize,ebx
	add	CurrentSize, ebx		;当前输出大小，以后逐步追加
	invoke	WriteFile, hFile,MapOfFile ,ebx,ADDR NumberOfBytesRW, NULL	;写文件头
	movzx	ecx,word ptr [esi].FileHeader.NumberOfSections
	mov	esi, offset PackSection
    PackNextSection:
	test	ecx,ecx
	jz	AllSectionPacked
	cmp	dword ptr [edi], 'adr.'
	jz	NotPack
	cmp	dword ptr [edi], 'ade.'
	jz	NotPack
	cmp	dword ptr [edi], 'rsr.'
	jz	PackResSection
	cmp	dword ptr [edi], 'oci.'
	jz	NotPack
	cmp	dword ptr [edi+10h], 0
	jz	NotPack
	;*********压缩**********
	mov	eax,dword ptr [edi+08h]		;区块映象大小
	mov	edx, 9
	mul	edx
	shr	eax,3
	add	eax,16
	mov	MEMSize,eax			;计算需要占用的内存空间
	push	ecx
	invoke	VirtualAlloc, NULL, eax, MEM_COMMIT, PAGE_READWRITE
	mov	MEM, eax
	mov	ebx,dword ptr [edi+0ch]		;区块映象偏移
	add	ebx,MapOfFile
	invoke	aP_pack,ebx,MEM,dword ptr[edi+08h],lpPackBuffer,0
	invoke	GetIntegral,eax,FileAlignment
	;*********保存各段属性,以备解压缩
	push	eax
	mov	eax,dword ptr[edi+08h]
	mov	dword ptr[esi],eax		;保存区块原大小__解压所需空间大小
	mov	eax,dword ptr[edi+0ch]
	mov	dword ptr[esi+4h],eax		;保存区块原偏移__解压起点
	pop	ebx
	mov	dword ptr[esi+8h],ebx		;保存压缩后大小__解压数量
	add	esi,0ch
	;*********
	mov	dword ptr[edi+10h],ebx		;修改段的文件大小
	mov	eax,CurrentSize
	mov	dword ptr[edi+14h], eax		;修改段的文件偏移
	add	CurrentSize, ebx		;改变当前文件大小
	invoke	WriteFile, hFile,MEM,ebx,ADDR NumberOfBytesRW, NULL	;写入段
	invoke	VirtualFree, MEM, 0, MEM_RELEASE
	pop	ecx
	jmp	PackDone
    PackResSection:
	.if	IsPackRes == 0h
		jmp	NotPack
	.endif
	;写入资源段不被压缩的部分
	push	ecx
	mov	eax,FirstResADDR		;最前面的资源的存放偏移
	sub	eax,dword ptr [edi+0ch]		;减区块基址后得不压缩部分长度
	mov	ecx,eax
	mov	ebx,dword ptr [edi+0ch]
	add	ebx,MapOfFile			;需写入的起点
	invoke	WriteFile, hFile,ebx,ecx,ADDR NumberOfBytesRW, NULL
	;************************
	mov	eax,dword ptr [edi+08h]	
	mov	edx, 9
	mul	edx
	shr	eax,3
	add	eax,16
	mov	MEMSize,eax			;计算需要占用的内存空间
	invoke	VirtualAlloc, NULL, MEMSize, MEM_COMMIT, PAGE_READWRITE
	mov	MEM, eax
	mov	ebx,FirstResADDR
	sub	ebx,dword ptr [edi+0ch]		;不压缩部分长度	
	mov	eax,dword ptr[edi+08h]
	sub	eax,ebx				;全段长度减不压缩部分得压缩部分长度
	push	eax				;需要压缩的字节数
	mov	ebx,FirstResADDR
	add	ebx,MapOfFile			;需压缩部分起点
	invoke	aP_pack,ebx,MEM,eax,lpPackBuffer,0
	pop	ebx
	mov	dword ptr[esi],ebx		;还原后长度
	mov	ebx,FirstResADDR
	mov	dword ptr[esi+4h],ebx		;还原起点
	mov	dword ptr[esi+8h],eax		;需还原部分长度
	add	esi,0ch
	mov	ebx,CurrentSize
	mov	dword ptr[edi+14h], ebx		;修改文件偏移
	mov	ebx,FirstResADDR
	sub	ebx,dword ptr[edi+0ch]		;不压缩部分长度
	add	ebx,eax				;加上压缩后长度
	invoke	GetIntegral,ebx,FileAlignment
	add	CurrentSize, eax
	mov	dword ptr[edi+10h], eax		;修改文件大小
	mov	ebx,FirstResADDR
	sub	ebx,dword ptr[edi+0ch]
	sub	eax,ebx				;块总长减已写入长度得此次写入长度
	mov	ebx,eax
	invoke	WriteFile, hFile,MEM,ebx,ADDR NumberOfBytesRW, NULL
	invoke	VirtualFree, MEM, 0, MEM_RELEASE
	pop	ecx
	jmp	PackDone
    NotPack:
	push	ecx
	mov	ecx,dword ptr [edi+0ch]		;区块映象偏移
	add	ecx,MapOfFile
	mov	edx,CurrentSize
	mov	dword ptr [edi+14h],edx		;写入文件偏移
	mov	eax,dword ptr [edi+10h]		;区块文件大小
	invoke	GetIntegral,eax,FileAlignment
	add	CurrentSize, eax
	mov	ebx,eax
	invoke	WriteFile, hFile,ecx,ebx,ADDR NumberOfBytesRW, NULL	;写入段
	pop	ecx
    PackDone:
	add	edi,28h
	dec	ecx
	jmp	PackNextSection
    AllSectionPacked:
	invoke	AddLine,ADDR M_PackFileOk
	popad
	ret
PackFile	endp
;***************处理外壳**********************************
DisposeShell	PROC
  LOCAL	ShellBufferMap	:DWORD
  LOCAL	ShellBufferMapUsed	:DWORD
  LOCAL	MEM		:DWORD
  LOCAL	MEMSize		:DWORD
  LOCAL	ShellSize	:DWORD
  LOCAL	ShellSize_NoPack:DWORD
  LOCAL	FunkCodeSize	:DWORD
	pushad
	invoke	VirtualAlloc, NULL, 20000h, MEM_COMMIT, PAGE_READWRITE
	mov	ShellBufferMap,eax
	;*******产生垃圾指令
	invoke	MakeFunkCode,ShellBufferMap
	mov	FunkCodeSize,eax
	;*******读入外壳
	mov	ecx,ShellEnd-ShellStart
	mov	ShellSize_NoPack,ecx
	lea	esi,ShellStart
	mov	edi,ShellBufferMap
	add	edi,FunkCodeSize
	rep	movsb
	;*******保存OEP
	mov	ebx,ShellBufferMap
	add	ebx,FunkCodeSize
	add	ebx,OEP-ShellStart
	mov	edx,PeHeadBase
	assume	edx : ptr IMAGE_NT_HEADERS
	mov	eax,dword ptr [edx].OptionalHeader.AddressOfEntryPoint
	mov	dword ptr [ebx],eax
	;*******保存是否处理输入表的标记
	mov	ebx,ShellBufferMap
	add	ebx,FunkCodeSize
	add	ebx,S_IsProtImpTable-ShellStart
	mov	eax,IsProtImpTable
	mov	dword ptr [ebx],eax
	;*******保存输入表地址
	.if	IsProtImpTable == 0
		mov	eax,dword ptr [edx].OptionalHeader.DataDirectory[SIZEOF IMAGE_DATA_DIRECTORY].VirtualAddress
		mov	ebx,ShellBufferMap
		add	ebx,FunkCodeSize
		add	ebx,ImpTableAddr-ShellStart
		mov	dword ptr [ebx],eax
	.else
		mov	eax,ShellSize_NoPack
		mov	ebx,ShellBufferMap
		add	ebx,FunkCodeSize
		add	ebx,ImpTableAddr-ShellStart
		mov	dword ptr [ebx],eax
		mov	edi,ShellBufferMap
		add	edi,FunkCodeSize
		add	edi,ShellSize_NoPack
		mov	esi,MapOfImpProt
		mov	ecx,MapOfImpProtUsed
		add	ShellSize_NoPack,ecx
		rep	movsb
	.endif
	;*******保存特殊代码加密信息
	.if	IsCodeProt == 1
		mov	ebx,ShellBufferMap
		add	ebx,FunkCodeSize
		add	ebx,S_IsCodeProt-ShellStart
		mov	dword ptr [ebx],1
		mov	eax,ShellSize_NoPack
		mov	ebx,ShellBufferMap
		add	ebx,FunkCodeSize
		add	ebx,CodeProtAddr-ShellStart
		mov	dword ptr [ebx],eax
		mov	edi,ShellBufferMap
		add	edi,FunkCodeSize
		add	edi,ShellSize_NoPack
		mov	esi,MapOfCodeProt
		mov	ecx,MapOfCodeProtUsed
		add	ShellSize_NoPack,ecx
		rep	movsb
	.endif
	;*******保存压缩块表信息
	mov	ecx,0a0h
	lea	esi,PackSection
	mov	edi,ShellBufferMap
	add	edi,FunkCodeSize
	add	edi,S_PackSection-ShellStart
	rep	movsb
	;*******
	mov	eax,FunkCodeSize
	add	ShellSize_NoPack,eax
	;*******压缩
	mov	eax,ShellSize_NoPack
	mov	edx, 9
	mul	edx
	shr	eax,3
	add	eax,16
	mov	MEMSize,eax			;计算需要占用的内存空间
	invoke	VirtualAlloc, NULL, eax, MEM_COMMIT, PAGE_READWRITE
	mov	MEM, eax
	invoke	aP_pack,ShellBufferMap,MEM,ShellSize_NoPack,lpPackBuffer,0
	mov	ShellBufferMapUsed,eax
	;*******读取外壳引导段**********
	mov	ecx,ShellEnd0-ShellStart0
	mov	ShellSize,ecx
	mov	edi,MapOfShell
	lea	esi,ShellStart0
	rep	movsb
	.if	IsPackRes == 1
		mov	ecx,MapOfPackResUsed
		add	ShellSize,ecx
		mov	esi,MapOfPackRes
		rep	movsb
	.endif
	;*******写入压缩后的外壳
	mov	ecx,ShellBufferMapUsed
	add	ShellSize,ecx
	mov	esi,MEM
	rep	movsb
	;*******修正外壳输入表
	mov	eax,PeImageSize
	add	eax,ImportTable-ShellStart0	;得到外壳输入表偏移
	mov	ebx,MapOfShell			;修改外壳输入表头
	add	ebx,ImportTable-ShellStart0
	add	dword ptr [ebx],eax
	mov	ebx,MapOfShell
	add	ebx,AppImpRVA1-ShellStart0
	add	dword ptr [ebx],eax
	mov	ebx,MapOfShell
	add	ebx,AppImpRVA2-ShellStart0
	add	dword ptr [ebx],eax
	mov	ebx,MapOfShell			;修改外壳输入地址表
	add	ebx,AddressFirst-ShellStart0
	add	dword ptr [ebx],eax
	mov	ebx,MapOfShell
	add	ebx,AddressSecond-ShellStart0
	add	dword ptr [ebx],eax
	mov	ebx,MapOfShell
	add	ebx,AddressThird-ShellStart0
	add	dword ptr [ebx],eax
	;*******保存外壳压缩资料,以备解压******
	mov	ebx,MapOfShell
	add	ebx,ShellBase-ShellStart0
	mov	eax,ShellEnd0-ShellStart0
	.if	IsPackRes == 1
		add	eax,MapOfPackResUsed
	.endif
	mov	dword ptr [ebx],eax
	mov	ebx,MapOfShell
	add	ebx,ShellPackSize-ShellStart0
	mov	eax,ShellSize_NoPack
	mov	dword ptr [ebx],eax
	;*******在文件头增加一个区段资料
	mov	edi,PeHeadBase
	assume	edi : ptr IMAGE_NT_HEADERS
	mov	eax,SecTableBase
	movzx	ecx,word ptr [edi].FileHeader.NumberOfSections
    ModifySectionCharact:
	or	dword ptr [eax+24h],0c0000000h
	add	eax,28h
	loop	ModifySectionCharact
	mov	esi,eax				;新块表起点
	push	edi
	mov	edi,esi
	xor	eax,eax
	mov	ecx,28h
	rep	stosb
	pop	edi
	mov	dword ptr [esi],'gcc.'
	invoke	GetIntegral,ShellSize,SectionAlignment
	mov	dword ptr [esi+08h],eax		;映象大小
	mov	eax,PeImageSize
	mov	dword ptr [esi+0ch],eax		;映象偏移
	invoke	GetIntegral,ShellSize,FileAlignment
	mov	dword ptr [esi+10h],eax		;文件大小
	mov	eax,dword ptr [esi-14h]
	add	eax,dword ptr [esi-18h]
	invoke	GetIntegral,eax,FileAlignment
	mov	dword ptr [esi+14h],eax		;文件偏移
	mov	dword ptr [esi+24h],0c0000040h
	inc	word ptr [edi].FileHeader.NumberOfSections	;区块数加一
	;*******修改文件头的一些资料
	mov	eax,PeImageSize
	mov	dword ptr [edi].OptionalHeader.AddressOfEntryPoint,eax	;修改EntryPoint
	invoke	GetIntegral,ShellSize,SectionAlignment
	add	eax,PeImageSize
	mov	dword ptr [edi].OptionalHeader.SizeOfImage,eax	;修改映象大小
	mov	eax,PeImageSize
	add	eax,ImportTable-ShellStart0			;修改输入表
	mov	dword ptr [edi].OptionalHeader.DataDirectory[SIZEOF IMAGE_DATA_DIRECTORY].VirtualAddress,eax
	mov	dword ptr [edi].OptionalHeader.DataDirectory[5*SIZEOF IMAGE_DATA_DIRECTORY].VirtualAddress,0h
	mov	dword ptr [edi].OptionalHeader.DataDirectory[5*SIZEOF IMAGE_DATA_DIRECTORY].isize,0h
	mov	dword ptr [edi].OptionalHeader.DataDirectory[11*SIZEOF IMAGE_DATA_DIRECTORY].VirtualAddress,0h
	mov	dword ptr [edi].OptionalHeader.DataDirectory[11*SIZEOF IMAGE_DATA_DIRECTORY].isize,0h
	mov	dword ptr [edi].OptionalHeader.DataDirectory[12*SIZEOF IMAGE_DATA_DIRECTORY].VirtualAddress,0h
	mov	dword ptr [edi].OptionalHeader.DataDirectory[12*SIZEOF IMAGE_DATA_DIRECTORY].isize,0h
	mov	esi,dword ptr [edi].OptionalHeader.DataDirectory[9*SIZEOF IMAGE_DATA_DIRECTORY].VirtualAddress
	.if	esi != 0
		add	esi,MapOfFile
		mov	eax,PeImageSize
		add	eax,TlsTable-ShellStart0
		mov	dword ptr [edi].OptionalHeader.DataDirectory[9*SIZEOF IMAGE_DATA_DIRECTORY].VirtualAddress,eax
		mov	edi,MapOfShell
		add	edi,TlsTable-ShellStart0
		mov	ecx,18h
		rep	movsb
	.endif
	invoke	VirtualFree, ShellBufferMap, 0, MEM_RELEASE
	popad
	invoke	GetIntegral,ShellSize,FileAlignment
	ret
DisposeShell	endp
;***************清空段名**************************
ClsSectionName	PROC
	pushad
	mov	esi,PeHeadBase
	assume	esi : ptr IMAGE_NT_HEADERS
	movzx	ecx,word ptr [esi].FileHeader.NumberOfSections
	mov	edi,SecTableBase	;块表起点
     ClsNextSecName:
	push	ecx
	mov	ecx,8h
	xor	eax,eax
	rep	stosb
	add	edi,20h
	pop	ecx
	loop	ClsNextSecName
	popad
	ret
ClsSectionName	endp
;***************清除重定位数据*********************
ClsRelocation	PROC
	pushad
	mov	edx,PeHeadBase
	mov	esi,dword ptr [edx].OptionalHeader.DataDirectory[5*SIZEOF IMAGE_DATA_DIRECTORY].VirtualAddress
	.if	esi == 0
		invoke	AddLine,ADDR M_NoRelocData
		popad
		ret
	.endif
	movzx	ecx,word ptr [edx].FileHeader.NumberOfSections
	mov	ebx,SecTableBase
    findRelSec:
	cmp	esi,dword ptr [ebx+0ch]
	jz	foundRelSec
	add	ebx,28h
	loop	findRelSec
	invoke	AddLine,ADDR M_NoRelocSec
	popad
	ret
    foundRelSec:
	mov	eax,dword ptr [ebx]
	.if	eax != 'ler.'
		invoke	AddLine,ADDR M_NoRelocSec
		popad
		ret
	.endif
	mov	edi,dword ptr [ebx+0ch]
	add	edi,MapOfFile
	mov	ecx,dword ptr [ebx+8h]
	xor	eax,eax
	rep	stosb
	mov	dword ptr [ebx+10h],0
	mov 	dword ptr [edx].OptionalHeader.DataDirectory[5*SIZEOF IMAGE_DATA_DIRECTORY].VirtualAddress,0
	mov	dword ptr [edx].OptionalHeader.DataDirectory[5*SIZEOF IMAGE_DATA_DIRECTORY].isize,0h
	invoke	AddLine,ADDR M_RelocClsOk
	popad
	ret
ClsRelocation	endp
;***************保存设置***************************
SaveTheSet	PROC
	pushad
	.if	IsSaveSet == 1
		.if	IsSaveSet == 1
			inc	I_issaveset_D
		.endif
		.if	IsCreateBak == 1
			inc	I_iscreatebak_D
		.endif
		.if	IsMergeSection == 1
			inc	I_Ismergesection_D
		.endif
		.if	IsPackRes == 1
			inc	I_Ispackres_D
		.endif
		.if	IsSaveSData == 1
			inc	I_Issavesdata_D
		.endif
		.if	IsProtImpTable == 1
			inc	I_Isprotimptable_D
		.endif
		.if	IsCodeProt == 1
			inc	I_Iscodeprot_D
		.endif
		.if	IsClsSecName == 1
			inc	I_Clssecname_D
		.endif
		.if	IsReFileHead == 1
			inc	I_IsReFileHead_D
		.endif
		.if	IsFileAlignment200 == 1
			inc	I_IsFileAlignment200_D
		.endif
		.if	IsNoRelocation == 1
			inc	I_IsNoRelocation_D
		.endif
		invoke	WritePrivateProfileString,addr IniSectionName,addr I_issaveset,addr I_issaveset_D,addr IniFileName
		invoke	WritePrivateProfileString,addr IniSectionName,addr I_iscreatebak,addr I_iscreatebak_D,addr IniFileName
		invoke	WritePrivateProfileString,addr IniSectionName,addr I_Ispackres,addr I_Ispackres_D,addr IniFileName
		invoke	WritePrivateProfileString,addr IniSectionName,addr I_Issavesdata,addr I_Issavesdata_D,addr IniFileName
		invoke	WritePrivateProfileString,addr IniSectionName,addr I_Iscodeprot,addr I_Iscodeprot_D,addr IniFileName
		invoke	WritePrivateProfileString,addr IniSectionName,addr I_Clssecname,addr I_Clssecname_D,addr IniFileName
		invoke	WritePrivateProfileString,addr IniSectionName,addr I_Ismergesection,addr I_Ismergesection_D,addr IniFileName
		invoke	WritePrivateProfileString,addr IniSectionName,addr I_Isprotimptable,addr I_Isprotimptable_D,addr IniFileName
		invoke	WritePrivateProfileString,addr IniSectionName,addr I_IsReFileHead,addr I_IsReFileHead_D,addr IniFileName
		invoke	WritePrivateProfileString,addr IniSectionName,addr I_IsFileAlignment200,addr I_IsFileAlignment200_D,addr IniFileName
		invoke	WritePrivateProfileString,addr IniSectionName,addr I_IsNoRelocation,addr I_IsNoRelocation_D,addr IniFileName
	.endif
	popad
	ret
SaveTheSet	endp
;***************产生垃圾指令***********************
MakeFunkCode	PROC	FuncCodeBase:DWORD
  LOCAL	FunkCodeSize:DWORD
	pushad
	mov	FunkCodeSize,0h
	mov	ecx,100h
	mov	edi,FuncCodeBase
    MakeNextFunkCode:
	push	ecx
	rdtsc
	and	eax,7h
	.if	eax == 0
		lea	esi,Junk_Code_1_Start
		mov	ecx,Junk_Code_1_End-Junk_Code_1_Start
		add	FunkCodeSize,ecx
		rep	movsb
	.elseif	eax == 1
		lea	esi,Junk_Code_2_Start
		mov	ecx,Junk_Code_2_End-Junk_Code_2_Start
		add	FunkCodeSize,ecx
		rep	movsb
	.elseif	eax == 2
		lea	esi,Junk_Code_3_Start
		mov	ecx,Junk_Code_3_End-Junk_Code_3_Start
		add	FunkCodeSize,ecx
		rep	movsb
	.elseif	eax == 3
		lea	esi,Junk_Code_4_Start
		mov	ecx,Junk_Code_4_End-Junk_Code_4_Start
		add	FunkCodeSize,ecx
		rep	movsb
	.elseif	eax == 4
		lea	esi,Junk_Code_5_Start
		mov	ecx,Junk_Code_5_End-Junk_Code_5_Start
		add	FunkCodeSize,ecx
		rep	movsb
	.elseif	eax == 5
		lea	esi,Junk_Code_6_Start
		mov	ecx,Junk_Code_6_End-Junk_Code_6_Start
		add	FunkCodeSize,ecx
		rep	movsb
	.elseif	eax == 6
		lea	esi,Junk_Code_7_Start
		mov	ecx,Junk_Code_7_End-Junk_Code_7_Start
		add	FunkCodeSize,ecx
		rep	movsb
	.elseif	eax == 7
		lea	esi,Junk_Code_8_Start
		mov	ecx,Junk_Code_8_End-Junk_Code_8_Start
		add	FunkCodeSize,ecx
		rep	movsb
	.endif
	xor	eax,eax
	pop	ecx
	dec	ecx
	jnz	MakeNextFunkCode
	popad
	mov	eax,FunkCodeSize
	ret
MakeFunkCode	endp
;***************找各个资源保存地址最前的一个,以后部分可以压缩
FindFirstResADDR	PROC
  LOCAL	FirstResAddr:DWORD
	push	edi
	push	esi
	push	ecx
	mov	FirstResAddr,7fffffffh
	mov	esi,PeHeadBase
	assume	esi : ptr IMAGE_NT_HEADERS
	mov	eax,dword ptr [esi].OptionalHeader.DataDirectory[2*SIZEOF IMAGE_DATA_DIRECTORY].VirtualAddress
	mov	esi,eax				;资源起点偏移
	add	eax,MapOfFile
	mov	edi,eax				;资源起点地址
	xor	ecx,ecx
	mov	cx,word ptr [edi+0ch]
	add	cx,word ptr [edi+0eh]		;有几类资源
	add	edi,10h
    SearchNextResType:
	push	ecx
	push	edi
	mov	edi,dword ptr [edi+4h]
	and	edi,7fffffffh			;该类型目录相对于资源起点的偏移
	add	edi,esi
	add	edi,MapOfFile			;该类型目录地址
	xor	ecx,ecx
	mov	cx,word ptr [edi+0ch]
	add	cx,word ptr [edi+0eh]		;该类型中有几个项目
	add	edi,10h
	    SearchNextResObject:	
		push	edi
		mov	edi,dword ptr [edi+4h]
		and	edi,7fffffffh		;该项目目录相对于资源起点的偏移
		add	edi,esi
		add	edi,MapOfFile		;该项目目录地址
		add	edi,10h
		mov	edi,dword ptr [edi+4h]	;该项目相对于资源起点的偏移
		add	edi,esi
		add	edi,MapOfFile		;该项目地址
		mov	eax,dword ptr [edi]	;该项目存放偏移
		.if	eax > esi
			.if	eax < FirstResAddr
				mov	FirstResAddr,eax
			.endif
		.endif
		pop	edi
		add	edi,8h
		loop	SearchNextResObject
	pop	edi
	pop	ecx
	add	edi,8h
	loop	SearchNextResType
	pop	ecx
	pop	esi
	pop	edi
	mov	eax,FirstResAddr
	ret
FindFirstResADDR	endp
;***************移动字符串***************************
MoveString	PROC	SourceStringADDR:DWORD,ObjectStringADDR:DWORD
;将源地址指向的以'00'结尾的字符串复制到目标地址指向的空间,并加密
;除eax外所有寄存器都不变,输出eax的值为复制的字节数
	push	edi
	push	esi
	push	ecx
	mov	edi,ObjectStringADDR
	mov	esi,SourceStringADDR
	xor	eax,eax
	xor	ecx,ecx
    MoveNextByte:
	lodsb
	.if	eax!=0
		stosb
		inc	ecx
	.else
		jmp	AllByteMoved
	.endif
	xor	eax,eax
	jmp	MoveNextByte
    AllByteMoved:
	mov	eax,ecx
	pop	ecx
	pop	esi
	pop	edi
	ret
MoveString	endp
;********************清除一个字符串********************************
ClsString	PROC	SourceStringADDR:DWORD
;将一个以'00'结束的字符串都清为'00'
	push	esi
	push	edi
	push	ecx
	mov	esi,SourceStringADDR
	mov	edi,SourceStringADDR
	xor	eax,eax
	xor	ecx,ecx
    ClsNextByte:
	lodsb
	.if	eax!=0
		xor	al,al
		stosb
		inc	ecx
	.else
		jmp	AllByteCls
	.endif
	xor	eax,eax
	jmp	ClsNextByte
    AllByteCls:
	mov	eax,ecx
	pop	ecx
	pop	edi
	pop	esi
	ret
ClsString	endp
;********************取整*************************************************
GetIntegral	PROC	SourceValue:DWORD,AlignmentValue:DWORD
;将SourceValue根据对齐值AlignmentValue进行取整,常用于对区块长度操作
;返回的值EAX即为取整后的值.
	push	edx
	push	ecx
	mov	eax,SourceValue
	mov	ecx,AlignmentValue
	xor	edx,edx
	div	ecx
	.if   edx!=0
		inc eax	
	.endif
	xor	edx,edx
	mul	AlignmentValue
	pop	ecx
	pop	edx
	ret
GetIntegral	endp
;********************在消息框中增加一行消息输出************************************
AddLine		PROC	LineToAdd: DWORD
  LOCAL	LineLength:DWORD
	pusha
	mov	esi,LineToAdd
	xor	eax,eax
    getlinelength:
	cmp	byte ptr [esi],0
	jz	Lengthgetted
	inc	eax
	inc	esi
	jmp	getlinelength
    Lengthgetted:	
	mov	LineLength, eax
	mov	edi, MessageBufferAddr	
	add	edi, DebugMsgSize
	mov	esi, LineToAdd
	mov	ecx, LineLength
	push	ecx
	shr	ecx, 2
	cld
	rep	movsd
	pop	ecx
	and 	ecx, 3
	rep	movsb
	mov	dword ptr [edi], 00000A0Dh
	mov	eax, LineLength
	add	DebugMsgSize, eax
	add	DebugMsgSize, 2
	invoke	SetDlgItemText, hProtDlg, IDC_MESSAGEBOX_EDIT, MessageBufferAddr
	invoke	SendDlgItemMessage, hProtDlg, IDC_MESSAGEBOX_EDIT, EM_GETLINECOUNT, 0, 0
	dec 	eax
	invoke	SendDlgItemMessage, hProtDlg, IDC_MESSAGEBOX_EDIT, EM_LINESCROLL, 0, eax
	popa
	ret
AddLine		endp
;*****************************************************
end start