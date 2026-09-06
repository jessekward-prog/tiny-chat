FROM node:22-alpine
WORKDIR /app
COPY server.js package.json ./
EXPOSE 8080
CMD ["node", "server.js"]
