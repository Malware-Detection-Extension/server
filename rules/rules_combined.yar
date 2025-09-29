import "pe"

// Word 문서 관련
include "./documents/doc.yar"
include "./documents/docx.yar"
include "./documents/pdf.yar"
include "./documents/txt.yar"
include "./documents/ppt.yar"
include "./documents/xls.yar"
include "./documents/xlsx.yar"

// 기타 포맷
include "./spreadsheets/base64_payloads.yar"
include "./images/hidden_payloads.yar"
include "./media/suspicious_metadata.yar"

// 실행 파일
include "./executables/suspicious_pe.yar"
include "./executables/packed_exe.yar"
include "./executables/malicious_scripts.yar"

// 압축/이메일
include "./archives/executable_in_archive.yar"
include "./emails/base64_payloads.yar"

