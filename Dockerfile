# Dockerfile

FROM python:3.10-slim

# 시스템 패키지 설치 (YARA 포함)
RUN apt-get update && apt-get install -y \
    libmagic1 \
    libmagic-dev \
    yara \
    libyara-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY logging_config.py .
COPY file_type.py .
COPY yara_scan.py .

RUN chmod +x app.py

CMD ["python3", "app.py"]
