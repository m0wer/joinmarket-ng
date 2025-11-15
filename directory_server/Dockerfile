FROM python:3.14-slim

WORKDIR /app

# Install jmcore dependencies first (cached layer)
COPY jmcore/requirements.txt /app/jmcore/requirements.txt
RUN pip install --no-cache-dir -r /app/jmcore/requirements.txt

# Copy jmcore source and install as editable
COPY jmcore /app/jmcore
RUN pip install --no-cache-dir -e /app/jmcore

# Copy directory_server source and install as editable (includes its dependencies)
COPY directory_server /app/directory_server
RUN pip install --no-cache-dir -e /app/directory_server

RUN useradd -m -u 1000 jm && \
    chown -R jm:jm /app

USER jm

EXPOSE 5222

ENV NETWORK=mainnet
ENV HOST=0.0.0.0
ENV PORT=5222
ENV LOG_LEVEL=INFO

CMD ["jm-directory-server"]
