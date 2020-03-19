FROM ubuntu:18.04

# Change example to the name of your challenge.
ENV USER black-hole

WORKDIR /home/$USER

RUN useradd $USER
RUN apt-get update
RUN apt-get install -y xinetd
RUN apt-get update
RUN apt-get install -y build-essential

COPY $USER.xinetd /etc/xinetd.d/$USER
COPY $USER.c /home/$USER/
COPY $USER.sh /home/$USER/
COPY Makefile /home/$USER/Makefile
COPY flag.txt /home/$USER/flag.txt

RUN make -C /home/$USER/

RUN chown -R root:$USER /home/$USER
RUN chmod -R 550 /home/$USER
RUN chmod -x /home/$USER/flag.txt

EXPOSE 13300

CMD service xinetd start && sleep 2 && tail -f /var/log/xinetdlog
