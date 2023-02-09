FROM python:3.10.9-alpine3.17 AS builder
LABEL org.opencontainers.image.source="https://github.com/DataDog/guarddog/"
RUN mkdir /app
# gcc and musl-dev needed for the pip install
RUN apk add --update gcc musl-dev g++ libgit2-dev libffi-dev
ADD . /app
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt

#FROM cgr.dev/chainguard/python:latest AS runner
#COPY --from=builder /app /app
#COPY --from=builder /usr/local/lib/python3.10/site-packages /app/site-packages
#ENV PYTHONPATH=/app/site-packages
WORKDIR /app
ENTRYPOINT ["python", "-m", "guarddog"]
