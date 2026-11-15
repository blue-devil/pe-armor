IDB_BITMAP		equ	2
IDB_BITMAP2		equ	3
IDD_MAKEKEYFILE		equ	6
IDC_TAB1		equ	8
IDC_OPEN_BUTTON		equ	3000
IDC_FILE_EDIT		equ	3001
IDC_MESSAGEBOX_EDIT	equ	3002
IDC_PROT_BUTTON		equ	3003
IDC_CLSSECNAME		equ	3011
IDC_MERGESECTION	equ	3012
IDC_PACKRES		equ	3013
IDC_SDATA		equ	3014
IDC_APIPROT		equ	3015
IDC_CODEPROT		equ	3016
IDC_REFILEHEAD		equ	3017
IDC_FA200		equ	3018
IDC_NOREL0		equ	3019
IDC_CREATEBAK		equ	3020
IDC_SAVESET		equ	3021
IDC_OPTIONOK		equ	3031
IDC_CCGSITE		equ	3041
IDC_IDESNUM		equ	3051
IDC_ONLYNUM		equ	3052
IDC_MAKEFILE0K		equ	3053
MAXSIZE			equ	512

DlgProc		proto :DWORD,:DWORD,:DWORD,:DWORD
ChildDlgProc1	proto :DWORD,:DWORD,:DWORD,:DWORD
ChildDlgProc2	proto :DWORD,:DWORD,:DWORD,:DWORD
ChildDlgProc3	proto :DWORD,:DWORD,:DWORD,:DWORD
FileIsExe	proto
ProtTheFile	proto
CreateBakFile	Proto :DWORD
ProtCode	proto
MoveImpTable	proto
ClsImpTable	proto
MoveRes		proto :DWORD,:DWORD,:DWORD
MergeSection	proto
PackFile	proto
DisposeShell	proto
ClsSectionName	proto
ClsRelocation	proto
SaveTheSet	proto
MakeFunkCode	proto :DWORD
FindFirstResADDR proto
AddLine		proto :DWORD
MoveString	Proto :DWORD,:DWORD
ClsString	Proto :DWORD
GetIntegral	Proto :DWORD,:DWORD

.DATA
MainDlgName	DB	"IDD_DIALOG1",0
Child1Name 	DB	"IDD_CHILD1",0
Child2Name	DB	"IDD_CHILD2",0
Child3Name	DB	"IDD_CHILD3",0
TabTitle1	DB	"处理",0
TabTitle2	DB	"选项",0
TabTitle3	DB	"关于",0
CcgSiteIp	DB	"http://ccg.abc.yesite.com/",0
FilterString	DB	"PE可执行文件(*.exe)",0,"*.exe",0,0
AboutText	DB	"hying's PE-Armor V 0.46",0dh,0ah
		DB	" Code by :  hying[CCG] ",0dh,0ah
		DB	" Copyright @ 2000-2001 ",0dh,0ah
		DB	" Licensed to :  Public ",0dh,0ah
		DB	" ********************* ",0dh,0ah
		DB	" Special Thanks go to: ",0dh,0ah
		DB	"          Hume         ",0dh,0ah
		DB	"          Ljtt         ",0dh,0ah
		DB	"        IceBird        ",0dh,0ah
		DB	" ********************* ",0dh,0ah
		DB	"    Contact Email :    ",0dh,0ah
		DB	"    h-ying@yeah.net    ",0
FontName	DB	"Courier New",0
;********************各种消息*************
M_FileOpenErr	DB	"错误!文件打开失败!",0
M_FileIsNotExe	DB	"错误!不是可执行文件!",0
M_FileIsNotPe	DB	"错误!不是标准的PE格式!",0
M_FileMaybeDll	DB	"错误!可能是PE-DLL文件!",0
M_FileIsPeExe	DB	"是PE-EXE文件,可以压缩.",0
M_ReadFileOK	DB	"文件读入完成.",0
M_VirtualAllocErr	DB	"申请使用内存失败.",0
M_MakeBakRight	DB	"创建备份成功.",0
M_MakeBakWrong	DB	"创建备份失败.",0
M_NoRelocData	DB	"未发现重定位数据.",0
M_NoRelocSec	DB	"未发现重定位区块.",0
M_RelocClsOk	DB	"重定位数据清除完成.",0
M_SaveSDataOK	DB	"额外数据保存完成.",0
M_HaveNoSData	DB	"没有额外数据.",0
M_CodeProtIsOver	DB	"特殊代码加密完成.",0
M_ImpTableProtIsOver	DB	"输入表加密完成.",0
M_PackResIsOver	DB	"资源处理完成.",0
M_MergeSectionIsOver	DB	"区段合并完成.",0
M_BeginPackFile	DB	"开始文件压缩，请稍等",0
M_PackFileOk	DB	"文件压缩完成.",0
;********************ini文件数据**********
IniFileName	DB	"prot.ini",0
IniSectionName	DB	"ProtSet",0
I_issaveset	DB	"SaveSet",0
I_issaveset_D	DB	"0",0
I_iscreatebak	DB	"CreateBak",0
I_iscreatebak_D	DB	"0",0
I_Ispackres	DB	"PackRes",0
I_Ispackres_D	DB	"0",0
I_Issavesdata	DB	"SaveSData",0
I_Issavesdata_D	DB	"0",0
I_Iscodeprot	DB	"CodeProt",0
I_Iscodeprot_D	DB	"0",0
I_Clssecname	DB	"ClsSecName",0
I_Clssecname_D	DB	"0",0
I_Ismergesection	DB	"MergeSection",0
I_Ismergesection_D	DB	"0",0
I_Isprotimptable	DB	"ProtImpTable",0
I_Isprotimptable_D	DB	"0",0
I_IsReFileHead		DB	"ReFileHead",0
I_IsReFileHead_D	DB	"0",0
I_IsFileAlignment200	DB	"FileAlignment200",0
I_IsFileAlignment200_D	DB	"0",0
I_IsNoRelocation	DB	"NoRelocation",0
I_IsNoRelocation_D	DB	"0",0
;*********选项标记**********
IsCreateBak	DD	0h
IsMergeSection	DD	0h
IsPackRes	DD	0h
IsSaveSData	DD	0h
IsProtImpTable	DD	0h
IsCodeProt	DD	0h
IsClsSecName	DD	0h
IsSaveSet	DD	0h
IsReFileHead	DD	0h
IsFileAlignment200	DD	0h
IsNoRelocation	DD	0h
.DATA?
hDc		DWORD		?
hMDc		DWORD		?
hMDc2		DWORD		?
hMDc3		DWORD		?
hBitMap		DWORD		?
hBrush		DWORD		?
TextOutX	DWORD		?
TextOutY	DWORD		?
TextOutCY	DWORD		?
;***************************
hInst	 	HINSTANCE 	?
hwndTab		HANDLE		?
hProtDlg	HANDLE		?
hProtButton	HANDLE		?
Handles LABEL	DWORD			;子窗口句柄
Child1hWnd	HANDLE		?
Child2hWnd	HANDLE		?
Child3hWnd	HANDLE		?
ItemStruct  	TC_ITEM 	<?>
WhichTabChosen		DD	?	;
MessageBufferAddr	DD	?	;消息框缓冲基址
DebugMsgSize		DD	?
Openfilename	OPENFILENAME	<?> 
FileName 	DB 	MAXSIZE dup(?)
LogFont		LOGFONT		<?>	
lpPackBuffer	DD		?
;********被保护文件的数据资料
hFile		DD		?
MapOfFile	DD		?
MapOfCodeProt	DD		?
MapOfCodeProtUsed	DD	?
MapOfImpProt	DD		?
MapOfImpProtUsed	DD	?
MapOfPackRes	DD		?
MapOfPackResUsed	DD	?
MapOfSData	DD		?
MapOfSDataUsed	DD		?
MapOfShell	DD		?
MapOfShellUsed	DD		?
CurrentSize	DD		?
PeHeadBase	DD		?
PeHeadSize	DD		?
SecTableBase	DD		?
PeImageSize	DD		?
PeImageBase	DD		?
SectionAlignment	DD	?
FileAlignment		DD	?
FirstResADDR		DD	?
PackSection	DB	0a0h dup (?)
;*********************************
FileDataEnd	DD		?
