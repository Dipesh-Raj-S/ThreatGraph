FROM httpd:2.4.49

# Enable mod_cgi / mod_cgid, open directory permissions, and configure ScriptAlias for CVE-2021-41773 RCE
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

# Ensure sample executable CGI script exists in cgi-bin
RUN printf '#!/bin/sh\necho "Content-Type: text/plain"\necho ""\necho "CGI Active"\n' > /usr/local/apache2/cgi-bin/test-cgi \
    && chmod +x /usr/local/apache2/cgi-bin/test-cgi

EXPOSE 80
