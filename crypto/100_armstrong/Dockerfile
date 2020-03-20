FROM ubuntu:18.04

# Change example to the name of your challenge.
ENV USER armstrong

RUN mkdir /home/$USER/
RUN useradd -ms /bin/bash $USER
RUN apt-get update
RUN apt-get install -y xinetd
RUN apt-get install -y python3
RUN apt-get install -y python3-pillow

COPY $USER.xinetd /etc/xinetd.d/$USER
COPY server.py /home/$USER/server.py
COPY book.txt /home/$USER/book.txt

RUN chown -R root:$USER /home/$USER
RUN chmod -R 550 /home/$USER
RUN touch /var/log/xinetdlog

# Change 1337 to your challenge port
EXPOSE 4001

CMD service xinetd start && sleep 2 && tail -f /var/log/xinetdlog