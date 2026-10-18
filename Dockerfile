# stationchief service: /otel (telemetry + storage) and /check (policy).
# TLS is terminated by the ingress or proxy in front of this container.
# The base is pinned by digest and the dependencies by hash. To refresh:
#   uv pip compile pyproject.toml --extra server --extra s3 --extra gcs \
#     --python-version 3.14 --universal --generate-hashes -o requirements-server.txt
# and take the new digest from `docker buildx imagetools inspect python:3.14-slim`.
FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

RUN useradd --create-home --uid 10001 stationchief
WORKDIR /app
COPY requirements-server.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements-server.txt
# Run from source instead of `pip install .`, which would pull an
# unpinned setuptools to build the package.
COPY stationchief ./stationchief

USER stationchief
EXPOSE 8080
CMD ["python", "-m", "stationchief.server.cli", "serve", "--host", "0.0.0.0", "--port", "8080"]
