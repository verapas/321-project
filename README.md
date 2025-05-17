# 321 Project – Simple WebSocket Chat App

A minimal chat application using Node.js, WebSocket, and MariaDB. Easily runnable via Docker Compose, with optional development mode support.

## Prerequisites

- Docker
- (Optional) Node.js >= 20.x (for development mode)

## How to Run (Production)

1. Make sure Docker and Docker Compose are installed.
2. Run:
   ```bash
   docker compose up -d
   ```
3. Access the frontend at: http://localhost:3000

The application uses the Docker image available at: https://hub.docker.com/r/pescel/321_project

## Development Mode (Optional)

If you want to run the app locally without Docker for development:

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start the MariaDB container:
   ```bash
   docker compose up -d mariadb phpmyadmin
   ```

3. Start the app in development mode:
   ```bash
   npm run dev
   ```

4. Access it at: http://localhost:3000

## Database Access

MariaDB is included and preconfigured in the Docker Compose setup.

### Default credentials:
- **Host**: mariadb
- **User**: mychat
- **Password**: mychatpassword
- **Database**: mychat

You can access the DB via terminal:
```bash
docker exec -it mariadb bash
mysql -u root -p
```

Or use PHPMyAdmin at: http://localhost:9200

## Reference

MariaDB Node.js connector guide: https://mariadb.com/kb/en/getting-started-with-the-nodejs-connector
