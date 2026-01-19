FROM python:3.10-slim-bullseye AS base
LABEL org.opencontainers.image.source="https://github.com/DataDog/guarddog/"

RUN addgroup --system --gid 1000 guarddog \
    && adduser --system --shell /bin/bash --uid 1000 --ingroup guarddog guarddog

WORKDIR /app


FROM base as builder
# only copy source for build
COPY . /app
# install any build time deps + Python deps
RUN --mount=type=cache,mode=0755,id=pip,target=/root/.cache/pip \
    pip install --root-user-action=ignore poetry \
    && poetry config virtualenvs.create false \
    && pip install .

FROM base as app
# copy built deps from builder
COPY --from=builder /usr/local/bin/ /usr/local/bin/
COPY --from=builder --chown=guarddog /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
USER guarddog
ENTRYPOINT ["guarddog"]
