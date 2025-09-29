import "hash"

// 📄 대상 확장자: .doc
// 🧩 대상 파일: Microsoft Word (OLE) 문서
// 🎯 탐지 목적: VBA 매크로, 자동 실행(AutoOpen 등), DDE/OLE 객체 삽입, 임베디드 PE/쉘코드 등 문서 기반 익스플로잇/매크로 드롭퍼 탐지

rule Suspicious_Doc_Macro
{
    meta:
        description = "Word 문서 내 매크로 또는 의심스러운 VBA 함수 탐지"
        author = "Seo"
        severity = "high"
        category = "document"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }     // OLE2 문서 시그니처 (.doc)
        $zip = { 50 4B 03 04 }                 // ZIP 기반 문서 (.docx, .docm)

        $macro1 = "Auto_Open" ascii wide nocase
        $macro2 = "Document_Open" ascii wide nocase
        $macro3 = "Workbook_Open" ascii wide nocase

        $vba1 = "Shell" ascii wide nocase
        $vba2 = "CreateObject" ascii wide nocase
        $vba3 = "GetObject" ascii wide nocase
        $vba4 = "URLDownloadToFile" ascii wide nocase
        $vba5 = "WScript.Shell" ascii wide nocase

    condition:
        (1 of ($ole, $zip)) and (1 of ($macro*)) and (1 of ($vba*))
}

rule Suspicious_Doc_AutoExecution
{
    meta:
        description = "문서 열람 시 자동 실행되는 매크로 탐지"
        author = "Seo"
        severity = "high"
        category = "document"

    strings:
        $auto1_ascii = "Auto_Open" ascii nocase
        $auto1_wide  = "Auto_Open" wide nocase
        $doc1_ascii  = "Document_Open" ascii nocase
        $doc1_wide   = "Document_Open" wide nocase
        $work1_ascii = "Workbook_Open" ascii nocase
        $work1_wide  = "Workbook_Open" wide nocase

    condition:
        any of them
}

rule Suspicious_Doc_VBA_Functions
{
    meta:
        description = "VBA 내 악성 가능성이 높은 함수 사용 탐지"
        author = "Seo"
        severity = "medium"
        category = "document"

    strings:
        $vba1 = "Shell" ascii wide nocase
        $vba2 = "CreateObject" ascii wide nocase
        $vba3 = "GetObject" ascii wide nocase
        $vba4 = "URLDownloadToFile" ascii wide nocase
        $vba5 = "WScript.Shell" ascii wide nocase

    condition:
        2 of ($vba*)
}

rule DOC_Uses_DDE
{
    meta:
        description = "Word 문서에서 DDE 명령 사용 탐지"
        author = "Seo"
        severity = "high"
        category = "document"

    strings:
        $dde1 = "DDEAUTO" ascii nocase
        $dde2 = "DDE" ascii nocase
        $cmd = "cmd.exe" ascii nocase

    condition:
        $dde1 or ($dde2 and $cmd)
}

rule DOC_Enc_Powershell
{
    meta:
        description = "Base64로 인코딩된 powershell 명령 탐지"
        author = "Seo"
        severity = "high"
        category = "document"

    strings:
        $b64 = "FromBase64String" ascii nocase
        $iex = "IEX" ascii nocase
        $ps = "powershell" ascii nocase

    condition:
        2 of them
}

rule DOC_Social_Engineering_Strings
{
    meta:
        description = "악성 lure 문서에 흔한 단어 포함"
        author = "Seo"
        severity = "low"
        category = "document"

    strings:
        $inv = "invoice" ascii nocase
        $pay = "payment" ascii nocase
        $acc = "account" ascii nocase
        $pass = "password" ascii nocase

    condition:
        2 of them
}

rule DOC_Embedded_PE
{
    meta:
        description = "문서 안에 PE 실행파일 시그니처가 숨어 있을 경우"
        author = "Seo"
        severity = "high"
        category = "document"

    strings:
        $mz = { 4D 5A } // "MZ"

    condition:
        $mz
}

// 휴리스틱 기반 탐지 규칙들
rule DOC_Heuristic_RTF_Exploitation
{
    meta:
        description = "DOC RTF 기반 익스플로잇 패턴 탐지"
        author = "Kim"
        severity = "high"
        category = "heuristic"
        filetype = "doc|rtf"
        reference = "InQuest/yara-rules, CVE analysis"

    strings:
        $ole_signature = { D0 CF 11 E0 A1 B1 1A E1 }
        $rtf_header = "{\\rtf1" ascii nocase
        
        // RTF 익스플로잇 패턴들
        $objdata = "\\objdata" ascii nocase
        $objclass = "\\objclass" ascii nocase
        $objw = "\\objw" ascii nocase
        $objh = "\\objh" ascii nocase
        
        // CVE-2017-11882 관련 패턴
        $equation = "Equation.3" ascii
        $equation_native = "Equation.DSMT4" ascii
        
        // CVE-2018-0802 관련
        $package_moniker = "4f1e5b9d-d05c-4564-ba2e-2b0420311520" ascii nocase
        
        // 셸코드 패턴
        $shellcode_marker = /\\[0-9a-fA-F]{2}\\[0-9a-fA-F]{2}\\[0-9a-fA-F]{2}/ ascii
        $nop_sled = "909090" ascii nocase

    condition:
        ($ole_signature at 0 or $rtf_header at 0) and
        2 of ($objdata, $objclass, $objw, $objh) and
        (any of ($equation*) or $package_moniker or any of ($shellcode_marker, $nop_sled))
}

rule DOC_Heuristic_Macro_Dropper
{
    meta:
        description = "DOC 매크로 드로퍼 패턴 탐지"
        author = "Kim"
        severity = "high"
        category = "heuristic"
        filetype = "doc"
        reference = "0xdf blog analysis, Yara-Rules/rules"

    strings:
        $ole_signature = { D0 CF 11 E0 A1 B1 1A E1 }
        
        // 파일 드롭 관련 함수들
        $open_file = "Open" ascii wide nocase
        $create_file = "CreateTextFile" ascii wide nocase
        $write_file = "WriteLine" ascii wide nocase
        $close_file = "Close" ascii wide nocase
        
        // 임시 경로들
        $temp_path = "\\temp\\" ascii wide nocase
        $appdata_path = "\\AppData\\" ascii wide nocase
        $public_path = "\\Public\\" ascii wide nocase
        $startup_path = "\\Startup\\" ascii wide nocase
        
        // 실행 함수들
        $shell_execute = "ShellExecute" ascii wide nocase
        $wscript_run = "WScript.Shell" ascii wide nocase
        $process_start = "Process.Start" ascii wide nocase
        
        // 파일 확장자들
        $exe_drop = ".exe" ascii wide nocase
        $bat_drop = ".bat" ascii wide nocase
        $vbs_drop = ".vbs" ascii wide nocase
        $scr_drop = ".scr" ascii wide nocase

    condition:
        $ole_signature at 0 and
        2 of ($open_file, $create_file, $write_file, $close_file) and
        any of ($temp_path, $appdata_path, $public_path, $startup_path) and
        (any of ($shell_execute, $wscript_run, $process_start) and 
         any of ($exe_drop, $bat_drop, $vbs_drop, $scr_drop))
}

rule DOC_Heuristic_Anti_Analysis_Techniques
{
    meta:
        description = "DOC 안티 분석 기법 탐지"
        author = "Kim"
        severity = "medium"
        category = "heuristic"
        filetype = "doc"
        reference = "DarkenCode/yara-rules, malware analysis blogs"

    strings:
        $ole_signature = { D0 CF 11 E0 A1 B1 1A E1 }
        
        // 샌드박스/VM 탐지
        $vmware_detect = "VMware" ascii wide nocase
        $vbox_detect = "VirtualBox" ascii wide nocase
        $qemu_detect = "QEMU" ascii wide nocase
        $vm_detect = "vmsrvc" ascii wide nocase
        $vm_tools = "vmtools" ascii wide nocase
        
        // 분석 도구 탐지
        $wireshark = "wireshark" ascii wide nocase
        $procmon = "procmon" ascii wide nocase
        $ollydbg = "ollydbg" ascii wide nocase
        $ida_detect = "ida" ascii wide nocase
        
        // 시간 지연 기법
        $sleep_func = "Sleep" ascii wide nocase
        $timer_func = "Timer" ascii wide nocase
        $wait_func = "Wait" ascii wide nocase
        
        // 사용자 상호작용 확인
        $click_count = "ClickCount" ascii wide nocase
        $mouse_pos = "MousePosition" ascii wide nocase
        $key_state = "GetKeyState" ascii wide nocase
        
        // 환경 정보 수집
        $username = "Environ(\"USERNAME\")" ascii wide nocase
        $computer_name = "Environ(\"COMPUTERNAME\")" ascii wide nocase

    condition:
        $ole_signature at 0 and
        ((any of ($vmware_detect, $vbox_detect, $qemu_detect, $vm_detect, $vm_tools) or
          any of ($wireshark, $procmon, $ollydbg, $ida_detect)) and
         (any of ($sleep_func, $timer_func, $wait_func) or
          any of ($click_count, $mouse_pos, $key_state) or
          any of ($username, $computer_name)))
}

rule DOC_Heuristic_Malicious_URL_Patterns
{
    meta:
        description = "DOC 내 악성 URL 패턴 탐지"
        author = "Kim"
        severity = "medium"
        category = "heuristic"
        filetype = "doc"
        reference = "InQuest Labs analysis, URL threat intelligence"

    strings:
        $ole_signature = { D0 CF 11 E0 A1 B1 1A E1 }
        
        // 의심스러운 도메인 TLD들
        $suspicious_tld1 = /http[s]?:\/\/[a-zA-Z0-9.-]+\.tk[\/\s"]/ ascii nocase
        $suspicious_tld2 = /http[s]?:\/\/[a-zA-Z0-9.-]+\.ml[\/\s"]/ ascii nocase
        $suspicious_tld3 = /http[s]?:\/\/[a-zA-Z0-9.-]+\.ga[\/\s"]/ ascii nocase
        $suspicious_tld4 = /http[s]?:\/\/[a-zA-Z0-9.-]+\.cf[\/\s"]/ ascii nocase
        
        // URL 단축 서비스들
        $url_shortener1 = "bit.ly" ascii nocase
        $url_shortener2 = "tinyurl.com" ascii nocase
        $url_shortener3 = "t.co" ascii nocase
        $url_shortener4 = "goo.gl" ascii nocase
        
        // 의심스러운 파일 다운로드 URL
        $exe_download = /http[s]?:\/\/[^\/\s"]+\/[^\/\s"]*\.exe/ ascii nocase
        $payload_download = /http[s]?:\/\/[^\/\s"]+\/[^\/\s"]*\.(zip|rar|7z|bat|ps1|vbs)/ ascii nocase
        
        // IP 주소 직접 접근
        $direct_ip = /http[s]?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ ascii
        
        // DGA 패턴 (Domain Generation Algorithm)
        $dga_pattern = /http[s]?:\/\/[a-z]{10,}\.com/ ascii nocase

    condition:
        $ole_signature at 0 and
        (2 of ($suspicious_tld*) or 2 of ($url_shortener*) or
         any of ($exe_download, $payload_download) or $direct_ip or $dga_pattern)
}

rule DOC_Heuristic_Persistence_Mechanisms
{
    meta:
        description = "DOC 지속성 메커니즘 탐지"
        author = "Kim"
        severity = "medium"
        category = "heuristic"
        filetype = "doc"
        reference = "MITRE ATT&CK T1547, T1053"

    strings:
        $ole_signature = { D0 CF 11 E0 A1 B1 1A E1 }
        
        // 레지스트리 Run 키 조작
        $run_key1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $run_key2 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $reg_add = "RegWrite" ascii wide nocase
        
        // 시작프로그램 폴더
        $startup_folder = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii wide nocase
        
        // 작업 스케줄러
        $schtasks = "schtasks" ascii wide nocase
        $task_create = "/create" ascii wide nocase
        $task_scheduler = "Schedule.Service" ascii wide nocase
        
        // WMI 이벤트 구독
        $wmi_event = "Win32_ProcessStartTrace" ascii wide nocase
        $wmi_consumer = "ActiveScriptEventConsumer" ascii wide nocase
        
        // 서비스 생성
        $create_service = "CreateService" ascii wide nocase
        $sc_create = "sc create" ascii wide nocase
        
        // Office 애드인 등록
        $office_addin = "\\Microsoft\\Office\\Word\\Addins" ascii wide nocase
        $vsto_addin = "VSTOLoader" ascii wide nocase

    condition:
        $ole_signature at 0 and
        ((any of ($run_key*) and $reg_add) or $startup_folder or
         ($schtasks and $task_create) or $task_scheduler or
         any of ($wmi_event, $wmi_consumer) or 
         any of ($create_service, $sc_create) or
         any of ($office_addin, $vsto_addin))
}

rule DOC_Heuristic_Information_Gathering
{
    meta:
        description = "DOC 정보 수집 활동 탐지"
        author = "Kim"
        severity = "low"
        category = "heuristic"
        filetype = "doc"
        reference = "MITRE ATT&CK T1082, T1083"

    strings:
        $ole_signature = { D0 CF 11 E0 A1 B1 1A E1 }
        
        // 시스템 정보 수집
        $system_info = "SystemInfo" ascii wide nocase
        $win_version = "Win32_OperatingSystem" ascii wide nocase
        $computer_system = "Win32_ComputerSystem" ascii wide nocase
        $cpu_info = "Win32_Processor" ascii wide nocase
        
        // 네트워크 정보
        $network_config = "ipconfig" ascii wide nocase
        $network_adapter = "Win32_NetworkAdapter" ascii wide nocase
        $netstat = "netstat" ascii wide nocase
        
        // 프로세스/서비스 정보
        $process_list = "Win32_Process" ascii wide nocase
        $service_list = "Win32_Service" ascii wide nocase
        $tasklist = "tasklist" ascii wide nocase
        
        // 파일 시스템 정보
        $drive_info = "Win32_LogicalDisk" ascii wide nocase
        $dir_listing = "Dir(" ascii wide nocase
        $file_search = "FileSearch" ascii wide nocase
        
        // 사용자 계정 정보
        $user_account = "Win32_UserAccount" ascii wide nocase
        $whoami = "whoami" ascii wide nocase
        $net_user = "net user" ascii wide nocase

    condition:
        $ole_signature at 0 and
        (2 of ($system_info, $win_version, $computer_system, $cpu_info) or
         2 of ($network_config, $network_adapter, $netstat) or
         2 of ($process_list, $service_list, $tasklist) or
         2 of ($drive_info, $dir_listing, $file_search) or
         2 of ($user_account, $whoami, $net_user))
}

rule DOC_Heuristic_Credential_Harvesting
{
    meta:
        description = "DOC 자격증명 수집 활동 탐지"
        author = "Kim"
        severity = "medium"
        category = "heuristic"
        filetype = "doc"
        reference = "MITRE ATT&CK T1555, T1003"

    strings:
        $ole_signature = { D0 CF 11 E0 A1 B1 1A E1 }
        
        // 브라우저 자격증명
        $chrome_login = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii wide nocase
        $firefox_login = "\\Mozilla\\Firefox\\Profiles" ascii wide nocase
        $edge_login = "\\Microsoft\\Edge\\User Data\\Default\\Login Data" ascii wide nocase
        
        // Windows 자격증명
        $credential_manager = "Windows Credentials" ascii wide nocase
        $lsass_dump = "lsass.exe" ascii wide nocase
        $sam_file = "\\System32\\config\\SAM" ascii wide nocase
        
        // 이메일 클라이언트
        $outlook_pst = ".pst" ascii wide nocase
        $outlook_registry = "\\Microsoft\\Office\\Outlook\\Profiles" ascii wide nocase
        
        // 키로거 관련
        $keylogger1 = "GetAsyncKeyState" ascii wide nocase
        $keylogger2 = "SetWindowsHookEx" ascii wide nocase
        $keylogger3 = "WH_KEYBOARD" ascii wide nocase
        
        // 클립보드 모니터링
        $clipboard = "GetClipboardData" ascii wide nocase
        $clipboard_monitor = "WM_CLIPBOARDUPDATE" ascii wide nocase

    condition:
        $ole_signature at 0 and
        (any of ($chrome_login, $firefox_login, $edge_login) or
         any of ($credential_manager, $lsass_dump, $sam_file) or
         any of ($outlook_pst, $outlook_registry) or
         2 of ($keylogger*) or
         any of ($clipboard, $clipboard_monitor))
}

rule DOC_Heuristic_High_Risk_Combination
{
    meta:
        description = "DOC 고위험 패턴 조합 탐지"
        author = "Kim"
        severity = "critical"
        category = "heuristic"
        filetype = "doc"
        reference = "Comprehensive threat analysis"

    strings:
        $ole_signature = { D0 CF 11 E0 A1 B1 1A E1 }
        
        // 자동 실행
        $auto_exec = /Auto_Open|Document_Open/ ascii wide nocase
        
        // 네트워크 활동
        $network = /URLDownloadToFile|XMLHTTP|WinHttp|InternetOpen/ ascii wide nocase
        
        // 코드 실행
        $execution = /Shell|CreateObject|WScript\.Shell|cmd\.exe|powershell/ ascii wide nocase
        
        // 파일 조작
        $file_ops = /CreateTextFile|WriteLine|Open.*Binary|Put/ ascii wide nocase
        
        // 난독화
        $obfuscation = /Chr\(|&[Hh][0-9a-fA-F]|StrReverse|Replace\(/ ascii wide nocase
        
        // 환경 회피
        $evasion = /Sleep\(|Timer|VMware|VirtualBox/ ascii wide nocase
        
        // 지속성
        $persistence = /HKEY_.*\\Run|Startup|schtasks|CreateService/ ascii wide nocase

    condition:
        $ole_signature at 0 and $auto_exec and $network and $execution and
        (2 of ($file_ops, $obfuscation, $evasion, $persistence))
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

rule APT_OLE_JSRat : maldoc APT
{
meta:
	author = "Rahul Mohandas"
	Date = "2015-06-16"
    severity = "high"
	Description = "Targeted attack using Excel/word documents"
strings:
	$header = {D0 CF 11 E0 A1 B1 1A E1}
	$key1 = "AAAAAAAAAA"
	$key2 = "Base64Str" nocase
	$key3 = "DeleteFile" nocase
	$key4 = "Scripting.FileSystemObject" nocase
condition:
	$header at 0 and (all of ($key*) )
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule Maldoc_CVE_2017_11882 : Exploit {
    meta:
        description = "Detects maldoc With exploit for CVE_2017_11882"
        author = "Marc Salinas (@Bondey_m)"
        reference = "c63ccc5c08c3863d7eb330b69f96c1bcf1e031201721754132a4c4d0baff36f8"
        date = "2017-10-20"
        severity = "critical"
    strings:
        $doc = "d0cf11e0a1b11ae1"
        $s0 = "Equation"
        $s1 = "1c000000020"
        $h0 = {1C 00 00 00 02 00}

    condition: 
        (uint32be(0) == 0x7B5C7274 or $doc at 0 ) and $s0 and ($h0 or $s1)
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

rule CVE_2017_8759_Mal_Doc {
   meta:
      description = "Detects malicious files related to CVE-2017-8759 - file Doc1.doc"
      author = "Florian Roth"
      reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
      date = "2017-09-14"
      severity = "critical"
      hash1 = "6314c5696af4c4b24c3a92b0e92a064aaf04fd56673e830f4d339b8805cc9635"
   strings:
      $s1 = "soap:wsdl=http://" ascii wide nocase
      $s2 = "soap:wsdl=https://" ascii wide nocase

      $c1 = "Project.ThisDocument.AutoOpen" fullword wide
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 500KB and 2 of them )
}

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
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule Contains_DDE_Protocol
{
        meta:
                author = "Nick Beede"
                description = "Detect Dynamic Data Exchange protocol in doc/docx"
                reference = "https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/"
                date = "2017-10-19"
                filetype = "Office documents"
                severity = "high"
        
        strings:
                $doc = {D0 CF 11 E0 A1 B1 1A E1}
                $s1 = { 13 64 64 65 61 75 74 6F 20 } // !!ddeauto
                $s2 = { 13 64 64 65 20 } // !!dde
                $s3 = "dde" nocase
                $s4 = "ddeauto" nocase

        condition:
                ($doc at 0) and 2 of ($s1, $s2, $s3, $s4)
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-12-02
	Identifier: Phishing Gina Harrowell Dez 2015
*/

rule PHISH_02Dez2015_attach_P_ORD_C_10156_124658 {
	meta:
		description = "Phishing Wave - file P-ORD-C-10156-124658.xls"
		author = "Florian Roth"
		reference = "http://myonlinesecurity.co.uk/purchase-order-124658-gina-harrowell-clinimed-limited-word-doc-or-excel-xls-spreadsheet-malware/"
		date = "2015-12-02"
        severity = "medium"
		hash = "bc252ede5302240c2fef8bc0291ad5a227906b4e70929a737792e935a5fee209"
	strings:
		$s1 = "Execute" ascii
		$s2 = "Process WriteParameterFiles" fullword ascii
		$s3 = "WScript.Shell" fullword ascii
		$s4 = "STOCKMASTER" fullword ascii
		$s5 = "InsertEmailFax" ascii
	condition:
		uint16(0) == 0xcfd0 and filesize < 200KB and all of them
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
		filetype = "decompressed VBA macro code"
        severity = "high"
		
	strings:
		$a = "= Array(" // Array of bytes
		$b = "77, 90," // MZ
		$c = "33, 84, 104, 105, 115, 32, 112, 114, 111, 103, 114, 97, 109, 32, 99, 97, 110, 110, 111, 116, 32, 98, 101, 32, 114, 117, 110, 32, 105, 110, 32, 68, 79, 83, 32, 109, 111, 100, 101, 46," // !This program cannot be run in DOS mode.
	
	condition:
	 	all of them
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
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
rule hancitor_dropper : vb_win32api
{
  meta:
    author = "Jeff White - jwhite@paloaltonetworks @noottrak"
    date   = "18AUG2016"
    severity = "high"
    hash1  = "03aef51be133425a0e5978ab2529890854ecf1b98a7cf8289c142a62de7acd1a"
    hash2  = "4b3912077ef47515b2b74bc1f39de44ddd683a3a79f45c93777e49245f0e9848"
    hash3  = "a78972ac6dee8c7292ae06783cfa1f918bacfe956595d30a0a8d99858ce94b5a"

  strings:
    $api_01 = { 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 }  // VirtualAlloc
    $api_02 = { 00 52 74 6C 4D 6F 76 65 4D 65 6D 6F 72 79 00 }  // RtlMoveMemory
    $api_04 = { 00 43 61 6C 6C 57 69 6E 64 6F 77 50 72 6F 63 41 00 }  // CallWindowProcAi
    $magic  = { 50 4F 4C 41 }  // POLA

  condition:
    uint32be(0) == 0xD0CF11E0 and all of ($api_*) and $magic
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule maldoc_API_hashing : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        severity = "medium"
    strings:
        $a1 = {AC 84 C0 74 07 C1 CF 0D 01 C7 EB F4 81 FF}
        $a2 = {AC 84 C0 74 07 C1 CF 07 01 C7 EB F4 81 FF}
    condition:
        any of them
}

rule maldoc_indirect_function_call_1 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        severity = "medium"
    strings:
        $a = {FF 75 ?? FF 55 ??}
    condition:
        for any i in (1..#a): (uint8(@a[i] + 2) == uint8(@a[i] + 5))
}

rule maldoc_indirect_function_call_2 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        severity = "medium"
    strings:
        $a = {FF B5 ?? ?? ?? ?? FF 95 ?? ?? ?? ??}
    condition:
        for any i in (1..#a): ((uint8(@a[i] + 2) == uint8(@a[i] + 8)) and (uint8(@a[i] + 3) == uint8(@a[i] + 9)) and (uint8(@a[i] + 4) == uint8(@a[i] + 10)) and (uint8(@a[i] + 5) == uint8(@a[i] + 11)))
}

rule maldoc_indirect_function_call_3 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        severity = "medium"
    strings:
        $a = {FF B7 ?? ?? ?? ?? FF 57 ??}
    condition:
        $a
}

rule maldoc_find_kernel32_base_method_1 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        severity = "high"
    strings:
        $a1 = {64 8B (05|0D|15|1D|25|2D|35|3D) 30 00 00 00}
        $a2 = {64 A1 30 00 00 00}
    condition:
        any of them
}

rule maldoc_find_kernel32_base_method_2 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        severity = "high"
    strings:
        $a = {31 ?? ?? 30 64 8B ??}
    condition:
        for any i in (1..#a): ((uint8(@a[i] + 1) >= 0xC0) and (((uint8(@a[i] + 1) & 0x38) >> 3) == (uint8(@a[i] + 1) & 0x07)) and ((uint8(@a[i] + 2) & 0xF8) == 0xA0) and (uint8(@a[i] + 6) <= 0x3F) and (((uint8(@a[i] + 6) & 0x38) >> 3) != (uint8(@a[i] + 6) & 0x07)))
}

rule maldoc_find_kernel32_base_method_3 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        severity = "high"
    strings:
        $a = {68 30 00 00 00 (58|59|5A|5B|5C|5D|5E|5F) 64 8B ??}
    condition:
        for any i in (1..#a): (((uint8(@a[i] + 5) & 0x07) == (uint8(@a[i] + 8) & 0x07)) and (uint8(@a[i] + 8) <= 0x3F) and (((uint8(@a[i] + 8) & 0x38) >> 3) != (uint8(@a[i] + 8) & 0x07)))
}

rule maldoc_getEIP_method_1 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        severity = "high"
    strings:
        $a = {E8 00 00 00 00 (58|59|5A|5B|5C|5D|5E|5F)}
    condition:
        $a
}

rule maldoc_getEIP_method_4 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        severity = "high"
    strings:
        $a1 = {D9 EE D9 74 24 F4 (58|59|5A|5B|5C|5D|5E|5F)}
        $a2 = {D9 EE 9B D9 74 24 F4 (58|59|5A|5B|5C|5D|5E|5F)}
    condition:
        any of them
}

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

rule office_document_vba : maldoc
{
	meta:
		description = "Office document with embedded VBA"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-12-17"
        severity = "medium"
		reference = "https://github.com/jipegit/"

	strings:
		$officemagic = { D0 CF 11 E0 A1 B1 1A E1 }
		$zipmagic = "PK"

		$97str1 = "_VBA_PROJECT_CUR" wide
		$97str2 = "VBAProject"
		$97str3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F }

		$xmlstr1 = "vbaProject.bin"
		$xmlstr2 = "vbaData.xml"

	condition:
		($officemagic at 0 and any of ($97str*)) or ($zipmagic at 0 and any of ($xmlstr*))
}

rule Office_AutoOpen_Macro : maldoc {
	meta:
		description = "Detects an Microsoft Office file that contains the AutoOpen Macro function"
		author = "Florian Roth"
		date = "2015-05-28"
        severity = "high"
		hash1 = "4d00695d5011427efc33c9722c61ced2"
		hash2 = "63f6b20cb39630b13c14823874bd3743"
		hash3 = "66e67c2d84af85a569a04042141164e6"
		hash4 = "a3035716fe9173703941876c2bde9d98"
		hash5 = "7c06cab49b9332962625b16f15708345"
		hash6 = "bfc30332b7b91572bfe712b656ea8a0c"
		hash7 = "25285b8fe2c41bd54079c92c1b761381"
	strings:
		$s1 = "AutoOpen" ascii fullword
		$s2 = "Macros" wide fullword
	condition:
		uint32be(0) == 0xd0cf11e0 and all of ($s*) and filesize < 300000
}