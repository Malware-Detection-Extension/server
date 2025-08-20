# Dockerfile

FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    libmagic1 \
    yara \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# install python library
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy required files
COPY app.py .
COPY logging_config.py .
COPY file_type.py .
COPY yara_scan.py .
COPY analysis_engine.py .
COPY report_template.json .

# grant execution permissions
RUN chmod +x app.py

# run app.py
CMD ["python3", "app.py"]

