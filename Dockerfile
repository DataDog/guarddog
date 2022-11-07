FROM python:3.10-alpine3.16
LABEL org.opencontainers.image.source="https://github.com/DataDog/guarddog/"
RUN mkdir /app
# gcc and musl-dev needed for the pip install
RUN apk add --update gcc musl-dev
ADD . /app
WORKDIR /app
RUN pip install -r requirements.txt
ENTRYPOINT ["python", "-m", "guarddog"]