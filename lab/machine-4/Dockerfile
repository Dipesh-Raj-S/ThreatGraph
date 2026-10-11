FROM httpd:2.4.49

# Configure mod_cgi and permissions for verified CVE-2021-41773 lab target
RUN sed -i 's/#LoadModule cgid_module/LoadModule cgid_module/' conf/httpd.conf \
    && sed -i 's/#LoadModule cgi_module/LoadModule cgi_module/' conf/httpd.conf \
    && sed -i 's/#Include conf\/extra\/httpd-autoindex.conf/Include conf\/extra\/httpd-autoindex.conf/' conf/httpd.conf \
    && sed -i '/<Directory \/>/,/<\/Directory>/ s/Require all denied/Require all granted/' conf/httpd.conf \
    && echo 'ScriptAlias /cgi-bin/ "/usr/local/apache2/cgi-bin/"' >> conf/httpd.conf \
    && echo '<Directory "/usr/local/apache2/cgi-bin">' >> conf/httpd.conf \
    && echo '    AllowOverride None' >> conf/httpd.conf \
    && echo '    Options +ExecCGI' >> conf/httpd.conf \
    && echo '    Require all granted' >> conf/httpd.conf \
    && echo '</Directory>' >> conf/httpd.conf

# Add sample CGI script
RUN printf '#!/bin/sh\necho "Content-Type: text/plain"\necho ""\necho "CGI Active"\n' > /usr/local/apache2/cgi-bin/test-cgi \
    && chmod +x /usr/local/apache2/cgi-bin/test-cgi

COPY index.html /usr/local/apache2/htdocs/index.html

EXPOSE 80
