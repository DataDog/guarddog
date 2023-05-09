FROM python:3.10.11-bullseye

# gcc and musl-dev needed for the pip install
RUN apt update && apt install -y gcc musl-dev g++ libffi-dev libgit2-dev
RUN pip install guarddog
RUN apt install -y git jq unzip

# Download ~954 malicious pypi packages
COPY download_malicious_pypi_package.sh /opt/
RUN /bin/sh /opt/download_malicious_pypi_package.sh /opt/malicious_pypi_package/
ENV MALICIOUS_PYPI_PACKAGE="/opt/malicious_pypi_package/"

# Download legitimate top 1000 pypi packages
COPY download_legit_pypi_package.sh /opt/
RUN /bin/sh /opt/download_legit_pypi_package.sh /opt/legit_pypi_package/
ENV LEGIT_PYPI_PACKAGE="/opt/legit_pypi_package/"

COPY docker_run_test.sh /tmp/
ENTRYPOINT ["/bin/sh", "docker_run_test.sh"]
