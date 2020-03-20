FROM mysql:5.7

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y curl software-properties-common \
    && apt-get install -y python3 \
    && apt-get install -y python3-mysqldb

RUN curl -sL https://deb.nodesource.com/setup_12.x | bash -
RUN apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir init_files server_files
COPY entrypoint.sh /
COPY db_create.py /init_files/

WORKDIR /server_files
COPY package-lock.json .
COPY package.json .
RUN npm install
COPY server.js .
COPY templates ./templates
COPY static ./static

CMD ["mysqld"]
