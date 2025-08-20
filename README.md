# 악성코드 분석 및 탐지 서버

## 1. 개요

본 레포지토리는 URL 및 파일에 대한 정적 분석을 수행하여 악성 여부를 탐지하는 서버입니다. 사용자가 분석을 요청한 URL을 통해 파일을 다운로드하고, 다양한 분석 기술을 적용하여 종합적인 위험도를 평가합니다. 분석 결과는 JSON 형식으로 제공되며, 악성으로 탐지될 경우 상세 내용을 담은 PDF 보고서가 함께 생성됩니다.

## 2. 주요 기능

- **URL 분석**: XGBoost 머신러닝 모델을 사용하여 URL 자체의 악성 위험도를 예측합니다.
- **파일 정적 분석**:
    - 파일 기본 정보(크기, 타입, 해시) 분석
    - 파일 엔트로피 계산을 통한 패킹 또는 암호화 탐지
    - PE(Portable Executable) 파일 상세 분석 (헤더, 섹션, 임포트된 API 등)
    - 파일 내에 포함된 잠재적 위협 지표(IP, URL) 추출
- **YARA 룰 기반 스캐닝**: 사전에 정의된 YARA 룰셋을 이용하여 알려진 악성코드 패턴을 탐지합니다.
- **압축 파일 분석**: ZIP 아카이브 내부의 모든 파일을 재귀적으로 분석합니다.
- **도커 기반 격리 분석**: 외부 파일을 안전하게 분석하기 위해 도커 컨테이너 내에서 분석을 수행합니다.
- **보고서 생성**:
    - 모든 분석 결과를 종합한 JSON 보고서를 생성합니다.
    - 악성 파일로 판명될 경우, 주요 분석 정보를 요약한 PDF 보고서를 생성합니다.

## 3. 동작 방식

1.  **분석 요청**: 사용자가 Flask 서버의 `/analyze` 엔드포인트로 분석할 URL을 포함하여 POST 요청을 보냅니다.
2.  **URL 분석**: 서버는 먼저 입력된 URL을 머신러닝 모델을 통해 분석하여 위험도를 평가합니다.
3.  **워커 컨테이너 실행**: `controller.py`가 도커를 제어하여 `malware_worker` 이미지를 사용하는 새로운 분석 컨테이너를 실행합니다. 이때 분석할 URL을 환경 변수로 전달합니다.
4.  **파일 다운로드 및 분석**: 컨테이너 내부에서 실행되는 `app.py`는 전달받은 URL로부터 파일을 다운로드한 후, `analysis_engine.py`를 통해 상세한 정적 분석 및 YARA 스캔을 수행합니다.
5.  **결과 반환**: 분석이 완료되면, 컨테이너는 분석 결과를 JSON 형식으로 표준 출력(stdout)에 출력하고 종료됩니다.
6.  **결과 처리 및 보고**: `controller.py`는 컨테이너의 로그에서 JSON 결과를 파싱합니다. URL 분석 결과와 파일 분석 결과를 병합하고, 악성으로 판단되면 PDF 보고서를 생성한 후 최종 결과를 사용자에게 반환합니다.

## 4. 디렉터리 구조

```
/
├───analysis_engine.py      # 핵심 정적 분석 로직
├───app.py                  # 도커 컨테이너에서 실행되는 메인 분석 스크립트
├───controller.py           # 도커 컨테이너 생성 및 제어
├───docker-compose.yml      # Docker Compose 설정
├───Dockerfile              # 분석 환경용 Dockerfile
├───file_type.py            # 파일 타입 분석 유틸리티
├───flask_server.py         # 메인 Flask 웹 서버
├───logging_config.py       # 로깅 설정
├───pdf_report.py           # 악성 분석 PDF 보고서 생성
├───report_template.json    # JSON 보고서 템플릿
├───requirements.txt        # Python 의존성 목록
├───start.sh                # 서버 실행 스크립트
├───url_analyzer.py         # URL 분석기 (ML 모델 사용)
├───xgb_url_classifier.joblib # URL 분류용 XGBoost 모델
├───yara_scan.py            # YARA 스캐너
├───rules/                  # YARA 룰 디렉터리
└───__pycache__/
```

## 5. 실행 방법

**요구사항**: Docker, Python 3.8+

1.  **Docker 이미지 빌드**:
    ```bash
    docker build -t malware_worker .
    ```

2.  **Python 의존성 설치**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Flask 서버 실행**:
    ```bash
    ./start.sh
    ```
    또는
    ```bash
    python flask_server.py
    ```

4.  **분석 요청**:
    서버가 실행되면 `http://localhost:8080/analyze` 엔드포인트로 POST 요청을 보낼 수 있습니다.

    **요청 예시 (curl):**
    ```bash
    curl -X POST -H "Content-Type: application/json" \
    -d '{"url": "http://example.com/somefile.zip"}' \
    http://localhost:8080/analyze
    ```

## 6. 주요 의존성

-   **Flask**: 웹 서버 프레임워크
-   **Docker**: 컨테이너 기반 격리 분석
-   **YARA-python**: YARA 룰 매칭
-   **pefile**: PE 파일 분석
-   **scikit-learn, xgboost, pandas**: URL 분석 머신러닝 모델
-   **fpdf**: PDF 보고서 생성
