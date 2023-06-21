FROM python:3.10-alpine3.17 AS base
LABEL org.opencontainers.image.source="https://github.com/DataDog/guarddog/"

RUN --mount=type=cache,mode=0755,id=apk,target=/var/cache/apk \
    apk add --update libgit2 libffi
RUN addgroup --system --gid 1000 app \
    && adduser --system --shell /bin/bash --uid 1000 --ingroup app app

RUN mkdir /app
WORKDIR /app


FROM base as builder
# only copy source for build
COPY . /app
# install any build time deps + Python deps
RUN --mount=type=cache,mode=0755,id=apk,target=/var/cache/apk \
    apk add --update gcc musl-dev g++ libgit2-dev libffi-dev
RUN --mount=type=cache,mode=0755,id=pip,target=/root/.cache/pip \
    # install python deps
    pip install --root-user-action=ignore -r requirements.txt \
    # install package
    && pip install --root-user-action=ignore .


FROM base as app
# copy built deps from builder
COPY --from=builder /usr/local/bin/ /usr/local/bin/
COPY --from=builder /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
USER app
ENTRYPOINT ["guarddog"]
