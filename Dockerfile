FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN apt-get update && apt-get install -y nmap && pip install --no-cache-dir -r requirements.txt
ENTRYPOINT ["python3", "whoip.py"]
