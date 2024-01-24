# Use the latest httpd image as the base
FROM httpd:latest

# Create a simple HTML file to serve
RUN echo '<!DOCTYPE html><html><head><title>No authentication</title></head><body><h1>No authentication required</h1><p>You have successfully loaded the page</p></body></html>' > /usr/local/apache2/htdocs/index.html

EXPOSE 80

CMD ["httpd-foreground"]
