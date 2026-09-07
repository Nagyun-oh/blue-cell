FROM python:3.12-slim

WORKDIR /app

COPY server.py index.html ./

ENV PYTHONUNBUFFERED=1

CMD ["python", "server.py"]