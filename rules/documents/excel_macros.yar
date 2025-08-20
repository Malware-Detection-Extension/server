// 📄 대상 확장자: .xls, .xlsx, .xlsm
// 🧩 대상 파일: Microsoft Excel 스프레드시트
// 🎯 탐지 목적: 매크로 자동 실행, 외부 객체 실행, DDE 악용 등 행위 기반 탐지

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
