// 📄 대상 확장자: .docx, .docm
// 🧩 대상 파일: Word ZIP 기반 OOXML 문서
// 🎯 탐지 목적: ZIP 내부에 포함된 vbaProject.bin 또는 악성 XML 내 외부 실행 흔적 탐지

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
