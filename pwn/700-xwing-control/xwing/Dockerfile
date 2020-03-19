FROM archlinux:20200106

# Change example to the name of your challenge.
ENV USER xwing

WORKDIR /home/$USER

RUN useradd -ms /bin/bash $USER
RUN pacman -Sy gcc make xinetd --noconfirm

COPY $USER.xinetd /etc/rc.d/$USER
COPY $USER.c /home/$USER/
COPY memdump.c /home/$USER/
COPY memdump.h /home/$USER/
COPY $USER.Makefile /home/$USER/Makefile
COPY $USER.sh /home/$USER/$USER.sh
COPY flag1.txt /home/$USER/flag1.txt
COPY flag2.txt /home/$USER/flag2.txt
COPY flag3.txt /home/$USER/flag3.txt
COPY flag4.txt /home/$USER/flag4.txt

#COPY glibc-2.30-1-x86_64.pkg.tar.xz /home/$USER/
#RUN pacman -U /home/$USER/glibc-2.30-1-x86_64.pkg.tar.xz --noconfirm

RUN make -C /home/$USER/

RUN chown -R root:$USER /home/$USER
RUN chmod -R 550 /home/$USER
RUN chmod -x /home/$USER/flag1.txt
RUN chmod -x /home/$USER/flag2.txt
RUN chmod -x /home/$USER/flag3.txt
RUN chmod -x /home/$USER/flag4.txt
RUN touch /var/log/xinetdlog

# Change 1337 to your challenge port
EXPOSE 1337

CMD xinetd -f /etc/rc.d/$USER && sleep 2 && tail -f /var/log/xinetdlog
