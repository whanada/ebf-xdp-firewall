FROM python:3.12-slim
WORKDIR /app
COPY control /app/control
COPY ui /app/ui
RUN mkdir /state && chown -R 10001:10001 /state
USER 10001:10001
ENV DB_PATH=/state/firewall.db BIND=0.0.0.0 PORT=8080 PYTHONDONTWRITEBYTECODE=1
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
CMD ["python3", "control/server.py"]
