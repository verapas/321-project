# A simple chat app with websocket

## Prerequisites
- Docker
- Node >= 20.x

## Get Started
```bash
npm install
docker compose up -d # For the mariaDB
npm run dev # For development
npm run prod # For Production or Docker Init Command
```
Then acces the frontend at http://localhost:3000

## Get Started MariaDB
https://mariadb.com/kb/en/getting-started-with-the-nodejs-connector/
```bash
docker exec -it mariadb bash
mysql -u root -p
```
OR
- Go to PHPMyAdmin: http://localhost:9200