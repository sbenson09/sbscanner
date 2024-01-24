# Use the latest httpd image as the base
FROM httpd:latest

# Install apache2-utils to get the htpasswd utility, then cleanup
RUN apt-get update && \
    apt-get install -y apache2-utils && \
    htpasswd -bBc /usr/local/apache2/conf/.htpasswd root root && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create a simple HTML file to serve
RUN echo '<!DOCTYPE html><html><head><title>Authentication Succeeded</title></head><body><h1>Basic Authentication Succeeded</h1><p>You have successfully logged in.</p></body></html>' > /usr/local/apache2/htdocs/index.html

# Configure httpd for basic authentication
RUN echo '<Directory "/usr/local/apache2/htdocs">\n\
    AuthType Basic\n\
    AuthName "Restricted Content"\n\
    AuthUserFile "/usr/local/apache2/conf/.htpasswd"\n\
    Require valid-user\n\
</Directory>\n' >> /usr/local/apache2/conf/httpd.conf

EXPOSE 80

CMD ["httpd-foreground"]
