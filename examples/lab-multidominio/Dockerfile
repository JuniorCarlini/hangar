FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Marks the image (docker build --build-arg LAB_BUILD=2): rollback tests see
# which image answered.
ARG LAB_BUILD=1
ENV LAB_BUILD=$LAB_BUILD
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --uid 10001 --no-create-home lab
USER 10001
EXPOSE 8000
# With DATABASE_URL (Postgres in Hangar) the pre-deploy command migrates and
# seeds, once per deploy; alone (SQLite) the container does it on start.
CMD ["sh", "-c", "if [ -z \"$DATABASE_URL\" ]; then python manage.py migrate --noinput && python manage.py seed; fi; exec gunicorn lab.wsgi --bind 0.0.0.0:8000 --workers 2 --graceful-timeout 25 --access-logfile -"]
