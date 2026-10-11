FROM alpine:latest

# Install Pure-FTPd at image build time
RUN apk add --no-cache pure-ftpd \
    && mkdir -p /var/lib/ftp/public \
    && chown -R ftp:ftp /var/lib/ftp

# Copy harmless synthetic files to anonymous FTP directory
COPY synthetic_files/ /var/lib/ftp/public/

RUN chown -R ftp:ftp /var/lib/ftp/public \
    && chmod -R 755 /var/lib/ftp/public

EXPOSE 21 21100-21110

# Run Pure-FTPd in foreground as container main process
# -e: Anonymous access only
# -j: Auto-create home directory if needed
# -R: Prevent user chmod commands
# -p: Passive port range for container network
CMD ["/usr/sbin/pure-ftpd", "-e", "-j", "-R", "-p", "21100:21110"]
