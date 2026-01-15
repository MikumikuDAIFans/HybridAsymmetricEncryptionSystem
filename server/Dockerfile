# Stage 1: Builder
FROM python:3.11-alpine as builder

RUN apk add --no-cache build-base libffi-dev musl-dev openssl-dev cargo rust

WORKDIR /build
COPY requirements.txt .
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt

# Stage 2: Runner
FROM python:3.11-alpine

WORKDIR /app

RUN apk add --no-cache libffi openssl

COPY --from=builder /install /usr/local
COPY app /app

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
