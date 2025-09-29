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


// 파워포인트 관련 CVE yara rule
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule MSIETabularActivex
{
        meta:
            ref = "CVE-2010-0805"
            impact = 7
            hide = true
            author = "@d3t0n4t0r"
            severity = "high"
            category = "presentation"

        strings:
            $cve20100805_1 = "333C7BC4-460F-11D0-BC04-0080C7055A83" nocase fullword
            $cve20100805_2 = "DataURL" nocase fullword
            $cve20100805_3 = "true"
        
        condition:
            ($cve20100805_1 and $cve20100805_3) or (all of them)
}


/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule JavaDeploymentToolkit
{
   meta:
        ref = "CVE-2010-0887"
        impact = 7
        author = "@d3t0n4t0r"
        severity = "high"
        category = "presentation"

   strings:
        $cve20100887_1 = "CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA" nocase fullword
        $cve20100887_2 = "document.createElement(\"OBJECT\")" nocase fullword
        $cve20100887_3 = "application/npruntime-scriptable-plugin;deploymenttoolkit" nocase fullword
        $cve20100887_4 = "application/java-deployment-toolkit" nocase fullword
        $cve20100887_5 = "document.body.appendChild(" nocase fullword
        $cve20100887_6 = "launch("
        $cve20100887_7 = "-J-jar -J" nocase fullword
        
   condition:
      3 of them
}