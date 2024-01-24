# Use the latest NGINX image as the base
FROM nginx:latest

# Create a directory for storing the htpasswd file
RUN mkdir -p /etc/nginx/auth

# Install apache2-utils to get the htpasswd utility
RUN apt-get update && apt-get install -y apache2-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Generate an htpasswd file for basic authentication
RUN htpasswd -b -c /etc/nginx/auth/.htpasswd root wrongpassword

# Remove default nginx configuration files
RUN rm /etc/nginx/conf.d/default.conf

# Create a custom index.html
RUN echo '<!DOCTYPE html><html><head><title>Authentication Succeeded</title></head><body><h1>Basic Authentication Succeeded</h1><p>You have successfully logged in.</p></body></html>' > /usr/share/nginx/html/index.html

# Create a new default nginx configuration with basic auth for all locations
RUN echo 'server {\
    listen       80;\
    server_name  localhost;\
    location / {\
        auth_basic           "Restricted Content";\
        auth_basic_user_file /etc/nginx/auth/.htpasswd;\
        root   /usr/share/nginx/html;\
        index  index.html index.htm;\
    }\
}' > /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
