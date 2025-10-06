build:
  docker build --no-cache -t blaadam/tkurbx-planka .
rebuild:
  docker build -t blaadam/tkurbx-planka .
up:
  docker compose up -d
buildup:
  docker compose up -d --build
stop:
  docker compose stop
