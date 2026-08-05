FROM python:3.12-slim

RUN useradd --system --create-home --home-dir /opt/connector connector
WORKDIR /opt/connector
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --no-cache-dir .
RUN install -d -o connector -g connector -m 0700 /var/lib/enterprise-connector
VOLUME ["/var/lib/enterprise-connector"]
USER connector
ENTRYPOINT ["enterprise-connector"]
CMD ["run", "--config", "/etc/enterprise-connector/config.toml"]
