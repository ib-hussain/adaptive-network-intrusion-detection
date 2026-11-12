FROM python:3.12-slim
WORKDIR /app
COPY lab /app/lab
COPY src /app/src
CMD ["python", "-m", "lab.generate", "--help"]
