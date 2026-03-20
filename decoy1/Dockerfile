FROM python:3.11-slim

WORKDIR /app

COPY server.py .

RUN chmod +x server.py

EXPOSE 3000

CMD ["python3", "server.py"]
