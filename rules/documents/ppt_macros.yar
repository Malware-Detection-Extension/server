// 📄 대상 확장자: .ppt, .pptx, .pptm
// 🧩 대상 파일: Microsoft PowerPoint 프레젠테이션
// 🎯 탐지 목적: 슬라이드 기반 자동 실행, 외부 실행 호출, 링크 실행 등 탐지

rule PPT_AutoExecution_Macro
{
    meta:
        description = "PowerPoint 문서 내 자동 실행 매크로 함수 (SlideShowBegin 등)"
        author = "Seo"
        severity = "high"
        category = "presentation"

    strings:
        $open1 = "Auto_Open" ascii wide nocase
        $open2 = "SlideShowBegin" ascii wide nocase
        $open3 = "PresentationOpen" ascii wide nocase

    condition:
        any of them
}

rule PPT_External_Launch_Strings
{
    meta:
        description = "외부 프로그램 실행 또는 링크 실행 시도"
        author = "Seo"
        severity = "high"
        category = "presentation"

    strings:
        $shell = "Shell" ascii wide nocase
        $url = /http[s]?:\/\/[^\s]+/ ascii wide
        $lnk = ".lnk" ascii wide nocase
        $exe = ".exe" ascii wide nocase

    condition:
        2 of them
}

// 휴리스틱 기반 탐지 규칙들
rule PPT_Heuristic_Macro_Obfuscation
{
    meta:
        description = "PowerPoint 매크로 난독화 기법 탐지"
        author = "Kim"
        severity = "medium"
        category = "heuristic"
        filetype = "pptx|pptm|ppt"
        reference = "Neo23x0/signature-base"

    strings:
        // VBA 난독화 패턴들
        $hex_concat1 = /&[Hh][0-9a-fA-F]{2}/ ascii wide
        $chr_concat = /Chr\s*\(\s*[0-9]+\s*\)/ ascii wide nocase
        $asc_concat = /Asc\s*\(\s*[^)]+\s*\)/ ascii wide nocase
        $string_reverse = "StrReverse" ascii wide nocase
        
        // 문자열 결합 패턴
        $concat1 = /[a-zA-Z_]\w*\s*=\s*[a-zA-Z_]\w*\s*\&\s*[a-zA-Z_]\w*/ ascii wide
        $concat2 = /[a-zA-Z_]\w*\s*=\s*"[^"]*"\s*\&\s*"[^"]*"/ ascii wide
        
        // Base64나 인코딩 패턴
        $base64_decode = /[A-Za-z0-9+\/]{20,}={0,2}/ ascii wide
        $url_decode = /%[0-9a-fA-F]{2}/ ascii wide

    condition:
        2 of them
}

rule PPT_Heuristic_Suspicious_VBA_Functions
{
    meta:
        description = "PowerPoint 내 의심스러운 VBA 함수 조합"
        author = "Kim"
        severity = "high"
        category = "heuristic"
        filetype = "pptx|pptm|ppt"
        reference = "Neo23x0/signature-base, InQuest/awesome-yara"

    strings:
        // 파일 시스템 접근
        $filesystem1 = "CreateObject" ascii wide nocase
        $filesystem2 = "WScript.Shell" ascii wide nocase
        $filesystem3 = "Scripting.FileSystemObject" ascii wide nocase
        $filesystem4 = "ADODB.Stream" ascii wide nocase
        
        // 네트워크 관련
        $network1 = "WinHttp.WinHttpRequest" ascii wide nocase
        $network2 = "MSXML2.XMLHTTP" ascii wide nocase
        $network3 = "InternetExplorer.Application" ascii wide nocase
        $network4 = "URLDownloadToFile" ascii wide nocase
        
        // 프로세스 실행
        $exec1 = "Shell" ascii wide nocase
        $exec2 = "Run" ascii wide nocase
        $exec3 = "Exec" ascii wide nocase
        $exec4 = "ShellExecute" ascii wide nocase
        
        // 레지스트리 조작
        $registry1 = "RegWrite" ascii wide nocase
        $registry2 = "RegRead" ascii wide nocase
        $registry3 = "HKEY_" ascii wide nocase

    condition:
        (any of ($filesystem*) and any of ($network*)) or
        (any of ($exec*) and any of ($registry*)) or
        (3 of them)
}

rule PPT_Heuristic_PowerShell_Execution
{
    meta:
        description = "PowerPoint에서 PowerShell 실행 시도 탐지"
        author = "Kim"
        severity = "high"
        category = "heuristic"
        filetype = "pptx|pptm|ppt"
        reference = "target/halogen"

    strings:
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "pwsh" ascii wide nocase
        $ps3 = "PowerShell.exe" ascii wide nocase
        
        // PowerShell 매개변수들
        $param1 = "-ExecutionPolicy" ascii wide nocase
        $param2 = "-WindowStyle" ascii wide nocase  
        $param3 = "-EncodedCommand" ascii wide nocase
        $param4 = "-NoProfile" ascii wide nocase
        $param5 = "-NonInteractive" ascii wide nocase
        $param6 = "-Bypass" ascii wide nocase
        $param7 = "-Hidden" ascii wide nocase
        
        // PowerShell 명령어들
        $cmd1 = "Invoke-Expression" ascii wide nocase
        $cmd2 = "DownloadString" ascii wide nocase
        $cmd3 = "WebClient" ascii wide nocase
        $cmd4 = "Start-Process" ascii wide nocase

    condition:
        any of ($ps*) and (any of ($param*) or any of ($cmd*))
}

rule PPT_Heuristic_Mouse_Over_Actions
{
    meta:
        description = "PowerPoint Mouse Over 액션을 통한 악성 행위 탐지"
        author = "Kim"
        severity = "medium"
        category = "heuristic"
        filetype = "pptx|pptm|ppt"
        reference = "NVISO Labs blog post"

    strings:
        // Mouse over 이벤트들
        $mouseover1 = "ppActionHyperlink" ascii wide
        $mouseover2 = "MouseOver" ascii wide nocase
        $mouseover3 = "OnMouseOver" ascii wide nocase
        $mouseover4 = "ActionSettings" ascii wide nocase
        
        // 하이퍼링크 관련
        $hyperlink1 = "file://" ascii wide nocase
        $hyperlink2 = "Hyperlink" ascii wide nocase
        $hyperlink3 = "hlinkClick" ascii wide nocase
        
        // 실행 가능한 확장자들
        $exec_ext1 = ".exe" ascii wide nocase
        $exec_ext2 = ".scr" ascii wide nocase
        $exec_ext3 = ".bat" ascii wide nocase
        $exec_ext4 = ".cmd" ascii wide nocase
        $exec_ext5 = ".ps1" ascii wide nocase

    condition:
        any of ($mouseover*) and (any of ($hyperlink*) or any of ($exec_ext*))
}

rule PPT_Heuristic_Embedded_Objects
{
    meta:
        description = "PowerPoint 내 의심스러운 임베디드 객체 탐지"
        author = "Kim"
        severity = "medium"
        category = "heuristic"
        filetype = "pptx|pptm|ppt"
        reference = "Yara-Rules/rules repository"

    strings:
        // 임베디드 객체 관련
        $embed1 = "embeddings" ascii wide nocase
        $embed2 = "oleObject" ascii wide nocase
        $embed3 = "package" ascii wide nocase
        $embed4 = "objdata" ascii wide nocase
        
        // OLE 객체들
        $ole1 = "Word.Document" ascii wide nocase
        $ole2 = "Excel.Sheet" ascii wide nocase
        $ole3 = "Forms.HTML" ascii wide nocase
        $ole4 = "Package" ascii wide nocase
        
        // 실행 가능한 객체들
        $prog1 = "WScript.Shell" ascii wide nocase
        $prog2 = "Shell.Application" ascii wide nocase
        $prog3 = "InternetExplorer.Application" ascii wide nocase

    condition:
        any of ($embed*) and (any of ($ole*) or any of ($prog*))
}

rule PPT_Heuristic_Anti_Analysis
{
    meta:
        description = "PowerPoint 안티 분석 기법 탐지"
        author = "Kim"
        severity = "medium"
        category = "heuristic"
        filetype = "pptx|pptm|ppt"
        reference = "DeCyberGuardian/malware-analysis"

    strings:
        // 샌드박스 감지
        $sandbox1 = "VMware" ascii wide nocase
        $sandbox2 = "VirtualBox" ascii wide nocase
        $sandbox3 = "vmsrvc" ascii wide nocase
        $sandbox4 = "vmtools" ascii wide nocase
        
        // 분석 도구 감지
        $analysis1 = "wireshark" ascii wide nocase
        $analysis2 = "procmon" ascii wide nocase
        $analysis3 = "ollydbg" ascii wide nocase
        $analysis4 = "windbg" ascii wide nocase
        
        // 지연/우회 기법
        $delay1 = "Sleep" ascii wide nocase
        $delay2 = "Timer" ascii wide nocase
        $delay3 = "Wait" ascii wide nocase
        
        // 환경 확인
        $env1 = "Username" ascii wide nocase
        $env2 = "ComputerName" ascii wide nocase
        $env3 = "Domain" ascii wide nocase

    condition:
        (any of ($sandbox*) or any of ($analysis*)) and 
        (any of ($delay*) or any of ($env*))
}

rule PPT_Heuristic_Template_Injection
{
    meta:
        description = "PowerPoint 템플릿 인젝션 공격 패턴"
        author = "Kim"
        severity = "high"
        category = "heuristic"
        filetype = "pptx|pptm|ppt"
        reference = "sivolko/comprehensive-yara-rules"

    strings:
        // 원격 템플릿 로딩
        $template1 = "attachedTemplate" ascii wide nocase
        $template2 = "Target" ascii wide nocase
        $template3 = "TargetMode" ascii wide nocase
        
        // 원격 URL 패턴
        $url1 = /http[s]?:\/\/[^\s"'<>]+\.dot[mx]?/ ascii wide nocase
        $url2 = /http[s]?:\/\/[^\s"'<>]+\.pot[mx]?/ ascii wide nocase
        $url3 = /http[s]?:\/\/[^\s"'<>]+\.xlt[mx]?/ ascii wide nocase
        
        // 관계 설정
        $relationship = "Relationship" ascii wide nocase
        $external = "External" ascii wide nocase

    condition:
        any of ($template*) and any of ($url*) and ($relationship or $external)
}

rule PPT_Heuristic_Macro_AutoExec_Combination
{
    meta:
        description = "PowerPoint 매크로 자동실행 조합 패턴"
        author = "Kim"
        severity = "high"
        category = "heuristic"
        filetype = "pptx|pptm|ppt"
        reference = "Multiple GitHub repositories analysis"

    strings:
        // 자동실행 이벤트들
        $auto1 = "Auto_Open" ascii wide nocase
        $auto2 = "SlideShowBegin" ascii wide nocase  
        $auto3 = "PresentationOpen" ascii wide nocase
        $auto4 = "OnSlideShowPageChange" ascii wide nocase
        $auto5 = "OnSlideShowTerminate" ascii wide nocase
        
        // 파일 조작
        $file1 = "Open" ascii wide nocase
        $file2 = "Write" ascii wide nocase
        $file3 = "Copy" ascii wide nocase
        $file4 = "Delete" ascii wide nocase
        
        // 네트워크 활동
        $net1 = "URLDownloadToFile" ascii wide nocase
        $net2 = "WinHttpRequest" ascii wide nocase
        $net3 = "XMLHTTP" ascii wide nocase
        
        // 암호화/인코딩
        $crypto1 = "Base64" ascii wide nocase
        $crypto2 = "Decode" ascii wide nocase
        $crypto3 = "Encrypt" ascii wide nocase

    condition:
        any of ($auto*) and 
        ((any of ($file*) and any of ($net*)) or
         (any of ($net*) and any of ($crypto*)) or
         (2 of ($file*) and any of ($crypto*)))
}

rule PPT_Heuristic_Suspicious_Strings_Concentration
{
    meta:
        description = "PowerPoint 내 의심스러운 문자열 집중도 기반 탐지"
        author = "Kim"
        severity = "low"
        category = "heuristic"
        filetype = "pptx|pptm|ppt"
        reference = "Heuristic analysis patterns"

    strings:
        // 의심스러운 키워드들
        $susp1 = "payload" ascii wide nocase
        $susp2 = "exploit" ascii wide nocase
        $susp3 = "backdoor" ascii wide nocase
        $susp4 = "trojan" ascii wide nocase
        $susp5 = "malware" ascii wide nocase
        $susp6 = "virus" ascii wide nocase
        $susp7 = "rootkit" ascii wide nocase
        $susp8 = "keylogger" ascii wide nocase
        $susp9 = "stealer" ascii wide nocase
        $susp10 = "ransomware" ascii wide nocase
        
        // 실행 관련 키워드
        $exec1 = "execute" ascii wide nocase
        $exec2 = "invoke" ascii wide nocase
        $exec3 = "launch" ascii wide nocase
        $exec4 = "start" ascii wide nocase
        $exec5 = "run" ascii wide nocase

    condition:
        3 of ($susp*) or (2 of ($susp*) and 2 of ($exec*))
}
