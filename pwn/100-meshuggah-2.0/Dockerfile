FROM archlinux/base

# Change example to the name of your challenge.
ENV USER meshuggah

WORKDIR /home/$USER

RUN useradd -ms /bin/bash $USER
RUN pacman -Sy gcc make xinetd --noconfirm

COPY $USER.xinetd /etc/rc.d/$USER
COPY $USER.c /home/$USER/
COPY $USER.Makefile /home/$USER/Makefile
COPY $USER.sh /home/$USER/$USER.sh
COPY flag.txt /home/$USER/flag.txt

RUN make -C /home/$USER/

RUN chown -R root:$USER /home/$USER
RUN chmod -R 550 /home/$USER
RUN chmod -x /home/$USER/flag.txt
RUN touch /var/log/xinetdlog

# Change 1337 to your challenge port
EXPOSE 1337

CMD xinetd -f /etc/rc.d/$USER && sleep 2 && tail -f /var/log/xinetdlog
