FROM nginx:alpine

# Copy static files
COPY index.html /usr/share/nginx/html/
COPY style.css /usr/share/nginx/html/
COPY app.js /usr/share/nginx/html/

# Nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000
