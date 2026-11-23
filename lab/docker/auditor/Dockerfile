# SegCheck inside the office lab's auditor container (Linux runtime). The entrypoint is set by lab/docker/docker-compose.yml.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iputils-ping && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home segcheck
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY segcheck ./segcheck
COPY segcheck_web ./segcheck_web
COPY scripts ./scripts
COPY tests ./tests
COPY pytest.ini start_segcheck.py SegCheck.exe .gitignore ./
RUN chown -R segcheck /app
