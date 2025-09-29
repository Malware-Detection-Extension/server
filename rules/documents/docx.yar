import "hash"

// 📄 대상 확장자: .docx
// 🧩 대상 파일: Microsoft Word (OpenXML) 문서
// 🎯 탐지 목적: vbaProject.bin 존재 여부, 외부 관계(ExternalRelationship)·템플릿 인젝션, XML 기반 DDE/MSHTA 호출, 매크로 난독화/외부 다운로드 패턴 탐지

rule DOCX_Contains_MacroProject
{
    meta:
        description = "docx/docm 파일 내 vbaProject.bin 존재 여부"
        author = "Seo"
        severity = "high"
        category = "document"

    strings:
        $zip_header = { 50 4B 03 04 }                  // ZIP 시그니처
        $vba_full = "word/vbaProject.bin" ascii        // 전체 경로
        $vba_short = "vbaProject.bin" ascii            // 경로 없이도 커버

    condition:
        $zip_header at 0 and any of ($vba*)
}

rule DOCX_Suspicious_XML_Strings
{
    meta:
        description = "Word XML 구조 내 외부 실행 관련 문자열 포함"
        author = "Seo"
        severity = "medium"
        category = "document"

    strings:
        $url = /http[s]?:\/\/[^\s]+/ ascii
        $cmd = "cmd.exe" ascii nocase
        $ps1 = "powershell" ascii nocase
        $script = "<script" ascii nocase    // FP 방지를 위해 구체화

    condition:
        2 of them
}

rule DOCX_External_Relationship
{
    meta:
        description = "docx 문서 내 외부 관계 파일 또는 링크 포함 여부"
        author = "Seo"
        severity = "medium"
        category = "document"

    strings:
        $rels = "_rels/.rels" ascii
        $external = "ExternalRelationship" ascii
        $target = /Target=\"http[s]?:\/\/[^\"]+/ ascii

    condition:
        any of them
}

rule DOCX_OLE_Exploit_Like
{
    meta:
        description = "CVE-2017-0199 유형의 OLE 객체 삽입 가능성"
        author = "Seo"
        severity = "high"
        category = "document"

    strings:
        $ole = "oleObject" ascii nocase
        $packager = "packager.dll" ascii nocase
        $fileurl = /file:\/\/[^\s]+/ ascii

    condition:
        2 of them
}

rule DOCX_Embedded_Suspicious_Extensions
{
    meta:
        description = "docx 내부에 exe, js, vbs, ps1 등 의심 확장자 포함"
        author = "Seo"
        severity = "high"
        category = "document"

    strings:
        $exe = ".exe" ascii
        $js = ".js" ascii
        $vbs = ".vbs" ascii
        $ps1 = ".ps1" ascii

    condition:
        2 of them
}

// 휴리스틱 기반 탐지 규칙들
rule DOCX_Heuristic_Macro_Obfuscation
{
    meta:
        description = "DOCX 매크로 난독화 기법 탐지"
        author = "Kim"
        severity = "medium"
        category = "heuristic"
        filetype = "docx|docm"
        reference = "Yara-Rules/rules, Neo23x0/signature-base"

    strings:
        $zip_header = { 50 4B 03 04 }
        
        // VBA 난독화 패턴들
        $hex_string = /&[Hh][0-9a-fA-F]{2,}/ ascii
        $chr_concat = /Chr\s*\(\s*[0-9]+\s*\)/ ascii wide nocase
        $asc_function = /Asc\s*\([^)]+\)/ ascii wide nocase
        $str_reverse = "StrReverse" ascii wide nocase
        
        // Base64 인코딩 패턴
        $base64_pattern = /[A-Za-z0-9+\/]{20,}={0,2}/ ascii
        $decode_base64 = "DecodeBase64" ascii wide nocase
        
        // 문자열 조작
        $replace_func = "Replace(" ascii wide nocase
        $split_func = "Split(" ascii wide nocase
        $join_func = "Join(" ascii wide nocase
        
        // 동적 실행
        $eval_func = "Eval(" ascii wide nocase
        $execute_func = "Execute(" ascii wide nocase

    condition:
        $zip_header at 0 and 3 of them
}

rule DOCX_Heuristic_Auto_Execution_Vectors
{
    meta:
        description = "DOCX 자동 실행 벡터 탐지"
        author = "Kim"
        severity = "high"
        category = "heuristic"
        filetype = "docx|docm"
        reference = "InQuest/awesome-yara, DeCyberGuardian/malware-analysis"

    strings:
        $zip_header = { 50 4B 03 04 }
        
        // 자동 실행 매크로들
        $auto_open = "Auto_Open" ascii wide nocase
        $auto_exec = "AutoExec" ascii wide nocase
        $auto_new = "AutoNew" ascii wide nocase
        $auto_close = "AutoClose" ascii wide nocase
        $document_open = "Document_Open" ascii wide nocase
        $document_new = "Document_New" ascii wide nocase
        $document_close = "Document_Close" ascii wide nocase
        
        // Word 이벤트 핸들러
        $class_initialize = "Class_Initialize" ascii wide nocase
        $class_terminate = "Class_Terminate" ascii wide nocase
        
        // 외부 실행 함수들
        $shell_execute = "Shell" ascii wide nocase
        $create_object = "CreateObject" ascii wide nocase
        $get_object = "GetObject" ascii wide nocase

    condition:
        $zip_header at 0 and 2 of ($auto*, $document*, $class*) and any of ($shell_execute, $create_object, $get_object)
}

rule DOCX_Heuristic_Template_Injection
{
    meta:
        description = "DOCX 템플릿 인젝션 공격 패턴 탐지"
        author = "Kim"
        severity = "high"
        category = "heuristic"
        filetype = "docx|docm"
        reference = "sivolko/comprehensive-yara-rules"

    strings:
        $zip_header = { 50 4B 03 04 }
        
        // 템플릿 관련
        $settings_xml = "word/settings.xml" ascii
        $attached_template = "attachedTemplate" ascii
        
        // 외부 템플릿 URL 패턴
        $http_template = /r:id="rId[0-9]+" Target="http[s]?:\/\/[^"]+\.dot[mx]?"/ ascii
        $external_template = /Type="http:\/\/schemas\.openxmlformats\.org\/officeDocument\/2006\/relationships\/attachedTemplate"/ ascii
        
        // 관계 파일들
        $rels_file = "word/_rels/settings.xml.rels" ascii
        $external_target = /TargetMode="External"/ ascii
        
        // 의심스러운 도메인 패턴
        $suspicious_domain = /http[s]?:\/\/[a-zA-Z0-9-]+\.(tk|ml|ga|cf|top|bit\.ly|tinyurl\.com)/ ascii nocase

    condition:
        $zip_header at 0 and 
        ($settings_xml and $attached_template) and
        ($http_template or ($external_template and $external_target)) and
        ($rels_file or $suspicious_domain)
}

rule DOCX_Heuristic_ActiveX_Exploitation
{
    meta:
        description = "DOCX ActiveX 객체 악용 패턴 탐지"
        author = "Kim"
        severity = "high"
        category = "heuristic"
        filetype = "docx|docm"
        reference = "Yara-Rules/rules repository analysis"

    strings:
        $zip_header = { 50 4B 03 04 }
        
        // ActiveX 관련 구조
        $activex_xml = "word/activeX/" ascii
        $activex_control = "activeXControl" ascii
        $activex_properties = "activeXProperties" ascii
        
        // OLE 객체들
        $ole_object = "oleObject" ascii
        $ole_link = "oleLink" ascii
        
        // 위험한 ProgID들
        $wscript_shell = "WScript.Shell" ascii nocase
        $shell_application = "Shell.Application" ascii nocase
        $internet_explorer = "InternetExplorer.Application" ascii nocase
        $powershell_exe = "PowerShell" ascii nocase
        
        // Control 관련
        $classid = "classid" ascii nocase
        $object_tag = "<object" ascii nocase

    condition:
        $zip_header at 0 and
        (any of ($activex*, $ole*) and any of ($wscript_shell, $shell_application, $internet_explorer, $powershell_exe)) or
        ($object_tag and $classid and any of ($wscript_shell, $shell_application))
}

rule DOCX_Heuristic_Form_Field_Exploitation
{
    meta:
        description = "DOCX 폼 필드 악용 패턴 탐지"
        author = "Kim"
        severity = "medium"
        category = "heuristic"
        filetype = "docx|docm"
        reference = "RanjitPatil/Malicious-Document-Analysis"

    strings:
        $zip_header = { 50 4B 03 04 }
        
        // 폼 필드 관련
        $form_field = "formField" ascii
        $text_input = "textInput" ascii
        $check_box = "checkBox" ascii
        $drop_down = "dropDown" ascii
        
        // 매크로 연결
        $macro_name = "macroName" ascii
        $entry_macro = "entryMacro" ascii
        $exit_macro = "exitMacro" ascii
        
        // 이벤트 핸들러
        $on_entry = "onEntry" ascii
        $on_exit = "onExit" ascii
        $on_click = "onClick" ascii
        
        // 숨겨진 필드들
        $hidden_text = /w:color="[Ff][Ff][Ff][Ff][Ff][Ff]"/ ascii  // 흰색 텍스트
        $zero_height = /w:h="0"/ ascii
        $zero_width = /w:w="0"/ ascii

    condition:
        $zip_header at 0 and
        any of ($form_field, $text_input, $check_box, $drop_down) and
        (any of ($macro_name, $entry_macro, $exit_macro) or any of ($on_entry, $on_exit, $on_click)) and
        (any of ($hidden_text, $zero_height, $zero_width))
}

rule DOCX_Heuristic_DDE_Attack_Patterns
{
    meta:
        description = "DOCX DDE(Dynamic Data Exchange) 공격 패턴 탐지"
        author = "Kim"
        severity = "high"
        category = "heuristic"
        filetype = "docx|docm"
        reference = "CVE-2017-8570, CVE-2018-0802 analysis"

    strings:
        $zip_header = { 50 4B 03 04 }
        
        // DDE 관련 구조들
        $dde_auto = "DDEAUTO" ascii nocase
        $dde_link = "ddeLink" ascii
        $field_begin = "fldChar" ascii
        
        // DDE 명령어 패턴들
        $cmd_exe = /cmd[^<]*\/c/ ascii nocase
        $powershell_cmd = /powershell[^<]*-/ ascii nocase
        $mshta_cmd = "mshta" ascii nocase
        $regsvr32_cmd = "regsvr32" ascii nocase
        
        // DDE 서비스/토픽 패턴
        $system_service = "system" ascii nocase
        $shell_service = "shell" ascii nocase
        
        // 인코딩된 DDE
        $encoded_dde = /\&[Hh][0-9a-fA-F]{2}/ ascii
        $unicode_dde = /\&#[0-9]{2,3};/ ascii

    condition:
        $zip_header at 0 and
        ($dde_auto or ($dde_link and $field_begin)) and
        (any of ($cmd_exe, $powershell_cmd, $mshta_cmd, $regsvr32_cmd) or
         (any of ($system_service, $shell_service) and any of ($encoded_dde, $unicode_dde)))
}

rule DOCX_Heuristic_XML_External_Entity
{
    meta:
        description = "DOCX XML External Entity (XXE) 공격 패턴 탐지"
        author = "Kim"
        severity = "medium"
        category = "heuristic"
        filetype = "docx|docm"
        reference = "OWASP XXE prevention cheat sheet"

    strings:
        $zip_header = { 50 4B 03 04 }
        
        // XML DOCTYPE 선언들
        $doctype = "<!DOCTYPE" ascii nocase
        $entity = "<!ENTITY" ascii nocase
        
        // External Entity 패턴들
        $system_entity = "SYSTEM" ascii nocase
        $public_entity = "PUBLIC" ascii nocase
        
        // 파일 접근 패턴들
        $file_protocol = "file://" ascii nocase
        $http_protocol = "http://" ascii nocase
        $ftp_protocol = "ftp://" ascii nocase
        
        // 민감한 파일 접근
        $etc_passwd = "/etc/passwd" ascii
        $windows_hosts = "C:\\Windows\\System32\\drivers\\etc\\hosts" ascii nocase
        $win_ini = "win.ini" ascii nocase
        
        // Entity 참조
        $entity_ref = /&[a-zA-Z][a-zA-Z0-9]*;/ ascii

    condition:
        $zip_header at 0 and
        $doctype and $entity and
        ($system_entity or $public_entity) and
        (any of ($file_protocol, $http_protocol, $ftp_protocol) or
         any of ($etc_passwd, $windows_hosts, $win_ini)) and
        $entity_ref
}

rule DOCX_Heuristic_Equation_Editor_Exploit
{
    meta:
        description = "DOCX Equation Editor 익스플로잇 패턴 탐지 (CVE-2017-11882, CVE-2018-0802)"
        author = "Kim"
        severity = "high"
        category = "heuristic"
        filetype = "docx|docm"
        reference = "CVE-2017-11882, CVE-2018-0802 analysis"

    strings:
        $zip_header = { 50 4B 03 04 }
        
        // Equation Editor 관련
        $equation = "Microsoft Equation" ascii
        $equation_native = "Equation.3" ascii
        $equation_ole = "Equation.DSMT4" ascii
        $math_type = "MathType" ascii
        
        // OLE 패키지 관련
        $ole_package = "Package" ascii
        $ole_stream = "Ole10Native" ascii
        
        // 셸코드 패턴들
        $shellcode_pattern1 = { 90 90 90 90 }  // NOP sled
        $shellcode_pattern2 = /\\x[0-9a-fA-F]{2}/ ascii
        $shellcode_pattern3 = /%u[0-9a-fA-F]{4}/ ascii
        
        // 익스플로잇 관련 명령어들
        $cmd_calc = "calc" ascii nocase
        $cmd_shell = "cmd.exe" ascii nocase
        $powershell_b64 = "powershell" ascii nocase

    condition:
        $zip_header at 0 and
        (any of ($equation*, $math_type) or ($ole_package and $ole_stream)) and
        (any of ($shellcode_pattern*) or any of ($cmd_calc, $cmd_shell, $powershell_b64))
}

rule DOCX_Heuristic_Suspicious_Content_Types
{
    meta:
        description = "DOCX 의심스러운 콘텐츠 타입 탐지"
        author = "Kim"
        severity = "low"
        category = "heuristic"
        filetype = "docx|docm"
        reference = "Microsoft Office file format analysis"

    strings:
        $zip_header = { 50 4B 03 04 }
        $content_types = "[Content_Types].xml" ascii
        
        // 의심스러운 콘텐츠 타입들
        $vba_content = "application/vnd.ms-office.vbaProject" ascii
        $macro_enabled = "application/vnd.ms-word.document.macroEnabled.12" ascii
        $template_macro = "application/vnd.ms-word.template.macroEnabled.12" ascii
        
        // 비정상적인 콘텐츠 타입들
        $executable_content = "application/x-msdownload" ascii
        $binary_content = "application/octet-stream" ascii
        $script_content = "text/javascript" ascii
        $vbscript_content = "text/vbscript" ascii
        
        // ActiveX 관련
        $activex_content = "application/vnd.ms-office.activeX" ascii
        $control_content = "application/x-oleobject" ascii

    condition:
        $zip_header at 0 and $content_types and
        (($vba_content or $macro_enabled or $template_macro) and
         (any of ($executable_content, $binary_content, $script_content, $vbscript_content) or
          any of ($activex_content, $control_content)))
}

rule DOCX_Heuristic_High_Risk_Combination
{
    meta:
        description = "DOCX 고위험 패턴 조합 탐지"
        author = "Kim"
        severity = "critical"
        category = "heuristic"
        filetype = "docx|docm"
        reference = "Comprehensive malware analysis patterns"

    strings:
        $zip_header = { 50 4B 03 04 }
        
        // 매크로 존재
        $vba_project = "vbaProject.bin" ascii
        
        // 자동 실행
        $auto_execution = /Auto_Open|Document_Open|AutoExec/ ascii wide nocase
        
        // 외부 연결
        $external_connection = /http[s]?:\/\/|ExternalRelationship|TargetMode="External"/ ascii
        
        // 난독화
        $obfuscation = /Chr\(|&[Hh][0-9a-fA-F]|StrReverse|DecodeBase64/ ascii wide nocase
        
        // 실행 함수
        $execution = /Shell|CreateObject|WScript\.Shell|cmd\.exe|powershell/ ascii wide nocase
        
        // 숨김 기법
        $hiding = /State="Hidden"|Visible="0"|w:color="[Ff]{6}"/ ascii

    condition:
        $zip_header at 0 and
        $vba_project and $auto_execution and
        ($external_connection or $obfuscation) and
        $execution and $hiding
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
      severity = "high"
      reference = "https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html"
      date = "2018-09-13"
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

