FROM alpine:3.18

RUN apk add --no-cache openssh \
    && ssh-keygen -A \
    && echo 'root:threatgraph' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
