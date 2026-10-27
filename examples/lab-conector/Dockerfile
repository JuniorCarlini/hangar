FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --uid 10001 --no-create-home lab
USER 10001
EXPOSE 8000
CMD ["gunicorn", "conector.wsgi", "--bind", "0.0.0.0:8000", "--workers", "2", "--graceful-timeout", "25", "--access-logfile", "-"]
