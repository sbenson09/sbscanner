# Use the latest NGINX image as the base
FROM nginx:latest

# Create a custom index.html
RUN echo '<!DOCTYPE html><html><head><title>No authentication</title></head><body><h1>No authentication required</h1><p>You have successfully loaded the page</p></body></html>' > /usr/share/nginx/html/index.html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
