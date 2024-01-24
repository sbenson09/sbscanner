# Use the latest Nginx image from Docker Hub
FROM nginx:latest

# Install openssl to generate a self-signed SSL certificate and create .htpasswd for basic auth
RUN apt-get update && \
    apt-get install -y openssl apache2-utils && \
    rm -rf /var/lib/apt/lists/*

# Generate a self-signed SSL certificate
RUN mkdir -p /etc/ssl/certificates && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/certificates/nginx.key -out /etc/ssl/certificates/nginx.crt \
    -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com"

# Create a .htpasswd file with username 'root' and password 'root'
RUN htpasswd -cb /etc/nginx/.htpasswd root root

# Set up configuration files
COPY default.conf /etc/nginx/conf.d/default.conf

# Copy the HTML file to be served
COPY index.html /usr/share/nginx/html/index.html

# Expose port 443 for HTTPS
EXPOSE 443

# Start Nginx when the container has provisioned
CMD ["nginx", "-g", "daemon off;"]