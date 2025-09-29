// 📄 대상 확장자: .txt
// 🧩 대상 파일: 일반 텍스트 파일
// 🎯 탐지 목적: 스크립트 코드(배치/파워셸/JS) 임베딩, 의심스러운 URL/IP·명령어 패턴( powershell -EncodedCommand 등), 인코딩/난독화(유니코드 이스케이프, base64) 포함 여부 탐지

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

rule CVE_2017_8759_SOAP_txt {
   meta:
      description = "Detects malicious file in releation with CVE-2017-8759 - file exploit.txt"
      author = "Florian Roth"
      reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
      date = "2017-09-14"
      severity = "critical"
      hash1 = "840ad14e29144be06722aff4cc04b377364eeed0a82b49cc30712823838e2444"
   strings:
      $s1 = /<soap:address location="http[s]?:\/\/[^"]{8,140}.hta"/ ascii wide
      $s2 = /<soap:address location="http[s]?:\/\/[^"]{8,140}mshta.exe"/ ascii wide
   condition:
      ( filesize < 200KB and 1 of them )
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