FROM mysql:5.7

RUN apt-get update \
    && apt-get install -y python3 \
    && apt-get install -y python3-mysqldb \
    && apt-get install -y python3-pip

RUN pip3 install flask

RUN mkdir init_files server_files
RUN mkdir /server_files/logs
COPY entrypoint.sh /
COPY data /init_files/data
COPY static /server_files/static/
COPY db_create.py /init_files/
COPY server.py /server_files/
COPY templates /server_files/templates/

CMD ["mysqld"]
