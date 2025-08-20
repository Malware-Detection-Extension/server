// 📄 대상 확장자: .doc, .docm
// 🧩 대상 프로그램: Microsoft Word
// 🎯 탐지 목적: 매크로 함수 + 악성 VBA 패턴 탐지

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
