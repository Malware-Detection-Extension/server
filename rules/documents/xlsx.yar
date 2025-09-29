import "hash"

// 📄 대상 확장자: .xlsx
// 🧩 대상 파일: Microsoft Excel (OpenXML, .xlsx/.xlsm) 스프레드시트
// 🎯 탐지 목적: vbaProject 존재·매크로 이벤트, 외부 연결/데이터연결(WEBSERVICE/ExternalData), XLM과 VBA 혼합 호출, 난독화·파일조작·네트워크 활동 패턴 탐지

rule Excel_Macro_AutoExecution
{
    meta:
        description = "Excel 문서 내 자동 실행 매크로 함수 (Workbook_Open 등)"
        author = "Seo"
        severity = "high"
        category = "spreadsheets"

    strings:
        $open1 = "Workbook_Open" ascii wide nocase
        $open2 = "Auto_Open" ascii wide nocase
        $run   = "Application.Run" ascii wide nocase

    condition:
        any of them
}

rule Excel_Macro_Exec_Functions
{
    meta:
        description = "Excel 매크로에서 외부 실행 관련 함수 사용 (Shell, CreateObject 등)"
        author = "Seo"
        severity = "high"
        category = "spreadsheets"

    strings:
        $shell = "Shell" ascii wide nocase
        $obj1 = "CreateObject" ascii wide nocase
        $obj2 = "GetObject" ascii wide nocase
        $url1 = "URLDownloadToFile" ascii wide nocase
        $wsh  = "WScript.Shell" ascii wide nocase

    condition:
        2 of them
}

rule Excel_DDE_Exploit
{
    meta:
        description = "DDEAUTO 또는 DDE 명령을 포함한 Excel 문서 (DDE 공격)"
        author = "Seo"
        severity = "medium"
        category = "spreadsheets"

    strings:
        $dde1 = "DDEAUTO" ascii nocase
        $dde2 = "DDE" ascii nocase
        $cmd = "cmd.exe" ascii nocase
        $ps1 = "powershell" ascii nocase

    condition:
        1 of ($dde*) and 1 of ($cmd, $ps1)
}

rule Excel_XLM_Macrosheet_Present
{
    meta:
        description = "Excel 문서에 Excel 4.0 macrosheet 포함"
        author = "Seo"
        severity = "medium"
        category = "spreadsheets"

    strings:
        $xlm = "Macrosheet" ascii
        $xlm2 = "Sheet Type=\"Macro\"" ascii

    condition:
        any of them
}

rule Excel_XLM_AutoOpen
{
    meta:
        description = "Excel 4.0 매크로에서 Auto_Open 또는 GET.WORKSPACE 사용"
        author = "Seo"
        severity = "high"
        category = "spreadsheets"

    strings:
        $auto = "Auto_Open" ascii
        $getws = "GET.WORKSPACE" ascii
        $xcall = "RUN" ascii

    condition:
        2 of them
}

rule Excel_XLM_Hidden_Macrosheet
{
    meta:
        description = "숨겨진 상태의 Excel 4.0 macrosheet 탐지"
        author = "Seo"
        severity = "high"
        category = "spreadsheets"

    strings:
        $hidden1 = "Visible=\"0\"" ascii
        $hidden2 = "State=\"Hidden\"" ascii
        $macrosheet = "Macrosheet" ascii

    condition:
        $macrosheet and 1 of ($hidden*)
}

// 휴리스틱 기반 탐지 규칙들
rule Excel_Heuristic_XLM_Obfuscation_Techniques
{
    meta:
        description = "Excel 4.0 매크로 난독화 기법 탐지"
        author = "Kim"
        severity = "medium"
        category = "heuristic"
        filetype = "xls|xlsx|xlsm"
        reference = "carbonblack/excel4-tests, InQuest/yara-rules"

    strings:
        // Excel 4.0 난독화 함수들
        $char_func = "CHAR(" ascii nocase
        $mid_func = "MID(" ascii nocase
        $code_func = "CODE(" ascii nocase
        $hex2dec = "HEX2DEC(" ascii nocase
        $formula_func = "FORMULA(" ascii nocase
        
        // 동적 문자열 구성
        $concatenate = "CONCATENATE(" ascii nocase
        $ampersand = /[A-Z][0-9]+&[A-Z][0-9]+/ ascii
        
        // 숫자 -> 문자 변환 패턴
        $char_pattern = /CHAR\([0-9]+\)/ ascii nocase
        $ascii_pattern = /[0-9]+,[0-9]+,[0-9]+/ ascii

    condition:
        3 of them or ($char_func and $concatenate) or ($hex2dec and $formula_func)
}

rule Excel_Heuristic_XLM_Execution_Patterns
{
    meta:
        description = "Excel 4.0 매크로 실행 패턴 조합 탐지"
        author = "Kim"
        severity = "high"
        category = "heuristic"
        filetype = "xls|xlsx|xlsm"
        reference = "carbonblack/excel4-tests, ReversingLabs research"

    strings:
        // 실행 함수들
        $exec_func = "EXEC(" ascii nocase
        $call_func = "CALL(" ascii nocase
        $register_func = "REGISTER(" ascii nocase
        
        // DLL 관련
        $kernel32 = "kernel32" ascii nocase
        $shell32 = "shell32" ascii nocase
        $urlmon = "urlmon" ascii nocase
        
        // API 함수들
        $virtualalloc = "VirtualAlloc" ascii nocase
        $writeprocessmemory = "WriteProcessMemory" ascii nocase
        $createthread = "CreateThread" ascii nocase
        $shellexecute = "ShellExecute" ascii nocase
        $urldownload = "URLDownloadToFile" ascii nocase

    condition:
        (any of ($exec_func, $call_func, $register_func) and any of ($kernel32, $shell32, $urlmon)) or
        (2 of ($virtualalloc, $writeprocessmemory, $createthread)) or
        ($urldownload and $shellexecute)
}

rule Excel_Heuristic_Environment_Detection
{
    meta:
        description = "Excel 환경 감지 및 샌드박스 회피 기법"
        author = "Kim"
        severity = "medium"
        category = "heuristic"
        filetype = "xls|xlsx|xlsm"
        reference = "carbonblack/excel4-tests analysis"

    strings:
        // 환경 정보 수집 함수들
        $get_workspace = "GET.WORKSPACE(" ascii nocase
        $get_document = "GET.DOCUMENT(" ascii nocase
        $get_window = "GET.WINDOW(" ascii nocase
        $get_workbook = "GET.WORKBOOK(" ascii nocase
        
        // 시스템 체크 관련
        $username_check = /GET\.WORKSPACE\(1\)/ ascii nocase
        $excel_version = /GET\.WORKSPACE\(2\)/ ascii nocase
        $windows_ver = /GET\.WORKSPACE\(13\)/ ascii nocase
        $mouse_present = /GET\.WORKSPACE\(19\)/ ascii nocase
        $sound_capability = /GET\.WORKSPACE\(42\)/ ascii nocase
        
        // 조건부 실행
        $if_func = "IF(" ascii nocase
        $iserror_func = "ISERROR(" ascii nocase

    condition:
        2 of ($get_*) and ($if_func or $iserror_func) and 
        (any of ($username_check, $excel_version, $windows_ver, $mouse_present, $sound_capability))
}

rule Excel_Heuristic_File_Operations
{
    meta:
        description = "Excel 매크로 내 파일 조작 기능 탐지"
        author = "Kim"
        severity = "medium"
        category = "heuristic"
        filetype = "xls|xlsx|xlsm"
        reference = "0xdf blog analysis, InQuest research"

    strings:
        // 파일 조작 함수들
        $fopen = "FOPEN(" ascii nocase
        $fwrite = "FWRITE(" ascii nocase
        $fwriteln = "FWRITELN(" ascii nocase
        $fread = "FREAD(" ascii nocase
        $freadln = "FREADLN(" ascii nocase
        $fclose = "FCLOSE(" ascii nocase
        $files = "FILES(" ascii nocase
        
        // 파일 경로 패턴
        $temp_path = "\\temp\\" ascii nocase
        $public_path = "\\public\\" ascii nocase
        $appdata_path = "\\appdata\\" ascii nocase
        $startup_path = "\\startup\\" ascii nocase
        
        // 실행 가능한 파일들
        $exe_ext = ".exe" ascii nocase
        $bat_ext = ".bat" ascii nocase
        $vbs_ext = ".vbs" ascii nocase
        $ps1_ext = ".ps1" ascii nocase

    condition:
        2 of ($f*) and (any of ($temp_path, $public_path, $appdata_path, $startup_path) or 
                       any of ($exe_ext, $bat_ext, $vbs_ext, $ps1_ext))
}

rule Excel_Heuristic_Network_Activity
{
    meta:
        description = "Excel 네트워크 활동 및 외부 데이터 연결"
        author = "Kim"
        severity = "high"
        category = "heuristic"
        filetype = "xls|xlsx|xlsm"
        reference = "Krishnendu.com research, InQuest labs"

    strings:
        // 네트워크 함수들
        $dconn = "DCONN(" ascii nocase
        $webservice = "WEBSERVICE(" ascii nocase
        
        // URL 패턴들
        $http_url = /http[s]?:\/\/[a-zA-Z0-9.-]+/ ascii nocase
        $ftp_url = /ftp:\/\/[a-zA-Z0-9.-]+/ ascii nocase
        
        // 외부 데이터 연결
        $external_data = "ExternalDataRange" ascii nocase
        $connection = "Connection" ascii nocase
        
        // 다운로드 관련
        $download = "download" ascii nocase
        $urlmon_dll = "urlmon.dll" ascii nocase

    condition:
        (any of ($dconn, $webservice) and any of ($http_url, $ftp_url)) or
        ($external_data and $connection) or
        ($urlmon_dll and $download)
}

rule Excel_Heuristic_VBA_XLM_Combination
{
    meta:
        description = "VBA와 Excel 4.0 매크로 조합 사용"
        author = "Kim"
        severity = "high"
        category = "heuristic"
        filetype = "xls|xlsx|xlsm"
        reference = "Multiple threat research analysis"

    strings:
        // VBA 관련
        $vba_project = "VBAProject" ascii nocase
        $application_run = "Application.Run" ascii nocase
        $evaluate = "Evaluate" ascii nocase
        
        // XLM 관련
        $macrosheet = "Macrosheet" ascii
        
        // 상호 호출 패턴
        $run_macro = /Run\s*\(\s*["'][^"']+["']\s*\)/ ascii nocase
        $execute_macro = /ExecuteExcel4Macro/ ascii nocase

    condition:
        ($vba_project and $macrosheet) and 
        (any of ($application_run, $evaluate, $run_macro, $execute_macro))
}

rule Excel_Heuristic_Persistence_Mechanisms
{
    meta:
        description = "Excel 지속성 메커니즘 탐지"
        author = "Kim"
        severity = "medium"
        category = "heuristic"
        filetype = "xls|xlsx|xlsm"
        reference = "MITRE ATT&CK techniques analysis"

    strings:
        // 레지스트리 관련
        $reg_write = /CALL\s*\(\s*["']advapi32["']\s*,\s*["']RegSetValueEx/ ascii nocase
        $reg_create = /CALL\s*\(\s*["']advapi32["']\s*,\s*["']RegCreateKey/ ascii nocase
        $hkey_current_user = "HKEY_CURRENT_USER" ascii nocase
        $hkey_local_machine = "HKEY_LOCAL_MACHINE" ascii nocase
        
        // 시작프로그램 관련
        $startup_folder = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii nocase
        $run_key = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
        
        // 작업 스케줄러
        $schtasks = "schtasks" ascii nocase
        $task_scheduler = "Schedule.Service" ascii nocase
        
        // 파일 복사/이동
        $copy_file = "CopyFile" ascii nocase
        $move_file = "MoveFile" ascii nocase
        $system32 = "\\system32\\" ascii nocase

    condition:
        (any of ($reg_write, $reg_create) and any of ($hkey_current_user, $hkey_local_machine)) or
        (any of ($startup_folder, $run_key)) or
        ($schtasks or $task_scheduler) or
        (any of ($copy_file, $move_file) and $system32)
}

rule Excel_Heuristic_Data_Exfiltration
{
    meta:
        description = "Excel 데이터 유출 패턴 탐지"
        author = "Kim"
        severity = "medium"
        category = "heuristic"
        filetype = "xls|xlsx|xlsm"
        reference = "Data exfiltration techniques research"

    strings:
        // HTTP 전송
        $http_post = /POST\s+http/ ascii nocase
        $xmlhttp = "XMLHTTP" ascii nocase
        $winhttp = "WinHttp" ascii nocase
        
        // 파일 업로드
        $upload = "upload" ascii nocase
        $send_data = "send" ascii nocase
        $post_data = "setRequestHeader" ascii nocase
        
        // 이메일 관련
        $outlook = "Outlook.Application" ascii nocase
        $mail_item = "MailItem" ascii nocase
        
        // FTP 관련
        $ftp_put = "FtpPutFile" ascii nocase
        $internet_open = "InternetOpen" ascii nocase
        
        // 데이터 수집
        $clipboard = "GetClipboardData" ascii nocase
        $keystroke = "GetKeyState" ascii nocase
        $screen_capture = "BitBlt" ascii nocase

    condition:
        (any of ($http_post, $xmlhttp, $winhttp) and any of ($upload, $send_data, $post_data)) or
        ($outlook and $mail_item) or
        (any of ($ftp_put, $internet_open)) or
        (2 of ($clipboard, $keystroke, $screen_capture))
}

rule Excel_Heuristic_High_Risk_Combination
{
    meta:
        description = "Excel 고위험 패턴 조합 탐지"
        author = "Kim"
        severity = "critical"
        category = "heuristic"
        filetype = "xls|xlsx|xlsm"
        reference = "Comprehensive malware analysis"

    strings:
        // 자동 실행
        $auto_exec = /Auto_Open|Workbook_Open/ ascii nocase
        
        // 숨겨진 시트
        $hidden = /Visible=\"0\"|State=\"Hidden\"|xlSheetVeryHidden/ ascii nocase
        
        // 네트워크 활동
        $network = /URLDownloadToFile|XMLHTTP|WinHttp/ ascii nocase
        
        // 코드 실행
        $execution = /EXEC\(|Shell|CreateObject|CALL\(/ ascii nocase
        
        // 난독화
        $obfuscation = /CHAR\(|HEX2DEC\(|CONCATENATE\(/ ascii nocase
        
        // 환경 감지
        $evasion = /GET\.WORKSPACE\(|GET\.DOCUMENT\(/ ascii nocase

    condition:
        $auto_exec and $hidden and ($network or $execution) and ($obfuscation or $evasion)
}

/* 

    from github

*/

/*
   Yara Rule Set
   Author: Colin Cowie
   Date: 2018-09-13
   Identifier: APT 10 (MenuPass)
   Reference: https://www.us-cert.gov/ncas/alerts/TA17-117A
*/

rule Maldoc_APT10_MenuPass {
   meta:
      description = "Detects APT10 MenuPass Phishing"
      author = "Colin Cowie"
      reference = "https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html"
      date = "2018-09-13"
      severity = "high"
   strings:
      $s1 = "C:\\ProgramData\\padre1.txt"
      $s2 = "C:\\ProgramData\\padre2.txt"
      $s3 = "C:\\ProgramData\\padre3.txt"
      $s5 = "C:\\ProgramData\\libcurl.txt"
      $s6 = "C:\\ProgramData\\3F2E3AB9"
   condition:
      any of them or
      hash.md5(0, filesize) == "4f83c01e8f7507d23c67ab085bf79e97" or
      hash.md5(0, filesize) == "f188936d2c8423cf064d6b8160769f21" or
      hash.md5(0, filesize) == "cca227f70a64e1e7fcf5bccdc6cc25dd"
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule FE_LEGALSTRIKE_MACRO {
       meta:version=".1"
       filetype="MACRO"
       author="Ian.Ahl@fireeye.com @TekDefense"
       date="2017-06-02"
       severity = "high"
       description="This rule is designed to identify macros with the specific encoding used in the sample 30f149479c02b741e897cdb9ecd22da7."
strings:
       // OBSFUCATION
       $ob1 = "ChrW(114) & ChrW(101) & ChrW(103) & ChrW(115) & ChrW(118) & ChrW(114) & ChrW(51) & ChrW(50) & ChrW(46) & ChrW(101)" ascii wide
       $ob2 = "ChrW(120) & ChrW(101) & ChrW(32) & ChrW(47) & ChrW(115) & ChrW(32) & ChrW(47) & ChrW(110) & ChrW(32) & ChrW(47)" ascii wide
       $ob3 = "ChrW(117) & ChrW(32) & ChrW(47) & ChrW(105) & ChrW(58) & ChrW(104) & ChrW(116) & ChrW(116) & ChrW(112) & ChrW(115)" ascii wide
       $ob4 = "ChrW(58) & ChrW(47) & ChrW(47) & ChrW(108) & ChrW(121) & ChrW(110) & ChrW(99) & ChrW(100) & ChrW(105) & ChrW(115)" ascii wide
       $ob5 = "ChrW(99) & ChrW(111) & ChrW(118) & ChrW(101) & ChrW(114) & ChrW(46) & ChrW(50) & ChrW(98) & ChrW(117) & ChrW(110)" ascii wide
       $ob6 = "ChrW(110) & ChrW(121) & ChrW(46) & ChrW(99) & ChrW(111) & ChrW(109) & ChrW(47) & ChrW(65) & ChrW(117) & ChrW(116)" ascii wide
       $ob7 = "ChrW(111) & ChrW(100) & ChrW(105) & ChrW(115) & ChrW(99) & ChrW(111) & ChrW(118) & ChrW(101) & ChrW(114) & ChrW(32)" ascii wide
       $ob8 = "ChrW(115) & ChrW(99) & ChrW(114) & ChrW(111) & ChrW(98) & ChrW(106) & ChrW(46) & ChrW(100) & ChrW(108) & ChrW(108)" ascii wide
       $obreg1 = /(\w{5}\s&\s){7}\w{5}/
       $obreg2 = /(Chrw\(\d{1,3}\)\s&\s){7}/
       // wscript
       $wsobj1 = "Set Obj = CreateObject(\"WScript.Shell\")" ascii wide
       $wsobj2 = "Obj.Run " ascii wide

condition:
        (
              (
                      (uint16(0) != 0x5A4D)
              )
              and
              (
                      all of ($wsobj*) and 3 of ($ob*)
                      or
                      all of ($wsobj*) and all of ($obreg*)
              )
       )
}
rule FE_LEGALSTRIKE_MACRO_2 {
       meta:version=".1"
       filetype="MACRO"
       author="Ian.Ahl@fireeye.com @TekDefense"
       date="2017-06-02"
       severity = "high"
       description="This rule was written to hit on specific variables and powershell command fragments as seen in the macro found in the XLSX file3a1dca21bfe72368f2dd46eb4d9b48c4."
strings:
       // Setting the environment
       $env1 = "Arch = Environ(\"PROCESSOR_ARCHITECTURE\")" ascii wide
       $env2 = "windir = Environ(\"windir\")" ascii wide
       $env3 = "windir + \"\\syswow64\\windowspowershell\\v1.0\\powershell.exe\"" ascii wide
       // powershell command fragments
       $ps1 = "-NoP" ascii wide
       $ps2 = "-NonI" ascii wide
       $ps3 = "-W Hidden" ascii wide
       $ps4 = "-Command" ascii wide
       $ps5 = "New-Object IO.StreamReader" ascii wide
       $ps6 = "IO.Compression.DeflateStream" ascii wide
       $ps7 = "IO.MemoryStream" ascii wide
       $ps8 = ",$([Convert]::FromBase64String" ascii wide
       $ps9 = "ReadToEnd();" ascii wide
       $psregex1 = /\W\w+\s+\s\".+\"/
condition:
       (
              (
                      (uint16(0) != 0x5A4D)
              )
              and
              (
                      all of ($env*) and 6 of ($ps*)
                      or
                      all of ($env*) and 4 of ($ps*) and all of ($psregex*)
              )
       )
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-09-14
   Identifier: Detects malicious files in releation with CVE-2017-8759
   Reference: https://github.com/Voulnet/CVE-2017-8759-Exploit-sample
*/

rule CVE_2017_8759_SOAP_Excel {
   meta:
      description = "Detects malicious files related to CVE-2017-8759"
      author = "Florian Roth"
      reference = "https://twitter.com/buffaloverflow/status/908455053345869825"
      date = "2017-09-15"
      severity = "high"
   strings:
      $s1 = "|'soap:wsdl=" ascii wide nocase
   condition:
      ( filesize < 300KB and 1 of them )
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
  Version 0.0.1 2016/03/21
  Source code put in public domain by Didier Stevens, no Copyright
  https://DidierStevens.com
  Use at your own risk

  Shortcomings, or todo's ;-) :

  History:
    2016/03/21: start
*/

rule Contains_VBE_File : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        description = "Detect a VBE file inside a byte sequence"
        method = "Find string starting with #@~^ and ending with ^#~@"
        severity = "medium"
    strings:
        $vbe = /#@~\^.+\^#~@/
    condition:
        $vbe
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Dridex_Trojan_XML : maldoc {
	meta:
		description = "Dridex Malware in XML Document"
		author = "Florian Roth @4nc4p"
		reference = "https://threatpost.com/dridex-banking-trojan-spreading-via-macros-in-xml-files/111503"
		date = "2015/03/08"
        severity = "critical"
		hash1 = "88d98e18ed996986d26ce4149ae9b2faee0bc082"
		hash2 = "3b2d59adadf5ff10829bb5c27961b22611676395"
		hash3 = "e528671b1b32b3fa2134a088bfab1ba46b468514"
		hash4 = "981369cd53c022b434ee6d380aa9884459b63350"
		hash5 = "96e1e7383457293a9b8f2c75270b58da0e630bea"
	strings:
		// can be ascii or wide formatted - therefore no restriction
		$c_xml      = "<?xml version="
		$c_word     = "<?mso-application progid=\"Word.Document\"?>"
		$c_macro    = "w:macrosPresent=\"yes\""
		$c_binary   = "<w:binData w:name="
		$c_0_chars  = "<o:Characters>0</o:Characters>"
		$c_1_line   = "<o:Lines>1</o:Lines>"
	condition:
		all of ($c*)
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Contains_hidden_PE_File_inside_a_sequence_of_numbers : maldoc
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect a hidden PE file inside a sequence of numbers (comma separated)"
		reference = "http://blog.didierstevens.com/2016/01/07/blackenergy-xls-dropper/"
		reference = "http://www.welivesecurity.com/2016/01/04/blackenergy-trojan-strikes-again-attacks-ukrainian-electric-power-industry/"
		date = "2016-01-09"
        severity = "high"
		filetype = "decompressed VBA macro code"
		
	strings:
		$a = "= Array(" // Array of bytes
		$b = "77, 90," // MZ
		$c = "33, 84, 104, 105, 115, 32, 112, 114, 111, 103, 114, 97, 109, 32, 99, 97, 110, 110, 111, 116, 32, 98, 101, 32, 114, 117, 110, 32, 105, 110, 32, 68, 79, 83, 32, 109, 111, 100, 101, 46," // !This program cannot be run in DOS mode.
	
	condition:
	 	all of them
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule Maldoc_Suspicious_OLE_target {
  meta:
    description =  "Detects maldoc With Tartgeting Suspicuios OLE"
    author = "Donguk Seo"
    reference = "https://blog.malwarebytes.com/threat-analysis/2017/10/decoy-microsoft-word-document-delivers-malware-through-rat/"
    filetype = "Office documents"
    date = "2018-06-13"
    severity = "high"
  strings:
    $env1 = /oleObject".*Target=.*.http.*.doc"/
    $env2 = /oleObject".*Target=.*.http.*.ppt"/
    $env3 = /oleObject".*Target=.*.http.*.xlx"/
  condition:
    any of them
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/


rule Contains_VBA_macro_code
{
	meta:
		author = "evild3ad"
		description = "Detect a MS Office document with embedded VBA macro code"
		date = "2016-01-09"
        severity = "medium"
		filetype = "Office documents"

	strings:
		$officemagic = { D0 CF 11 E0 A1 B1 1A E1 }
		$zipmagic = "PK"

		$97str1 = "_VBA_PROJECT_CUR" wide
		$97str2 = "VBAProject"
		$97str3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F } // Attribute VB_

		$xmlstr1 = "vbaProject.bin"
		$xmlstr2 = "vbaData.xml"

	condition:
		($officemagic at 0 and any of ($97str*)) or ($zipmagic at 0 and any of ($xmlstr*))
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule macrocheck : maldoc
{
    meta:
        Author      = "Fireeye Labs"
        Date        = "2014/11/30" 
        severity    = "high"
        Description = "Identify office documents with the MACROCHECK credential stealer in them.  It can be run against .doc files or VBA macros extraced from .docx files (vbaProject.bin files)."
        Reference   = "https://www.fireeye.com/blog/threat-research/2014/11/fin4_stealing_insid.html"

    strings:
        $PARAMpword = "pword=" ascii wide
        $PARAMmsg = "msg=" ascii wide
        $PARAMuname = "uname=" ascii
        $userform = "UserForm" ascii wide
        $userloginform = "UserLoginForm" ascii wide
        $invalid = "Invalid username or password" ascii wide
        $up1 = "uploadPOST" ascii wide
        $up2 = "postUpload" ascii wide
 
    condition:
        all of ($PARAM*) or (($invalid or $userloginform or $userform) and ($up1 or $up2))
}

