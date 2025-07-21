FROM python:3.11-slim
WORKDIR /app
COPY operator.py .
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
ENTRYPOINT ["kopf", "run", "--standalone", "operator.py"]

