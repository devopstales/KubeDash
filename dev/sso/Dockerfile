FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py .
EXPOSE 8888
HEALTHCHECK --interval=10s --timeout=3s --retries=5 --start-period=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8888/healthz')" || exit 1
CMD ["python", "server.py"]
