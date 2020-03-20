FROM php:7.4.2-cli-alpine

RUN mkdir server_files
COPY back.jpg /server_files/
COPY index.php /server_files/

RUN chown nobody:nogroup /server_files
USER nobody
WORKDIR /server_files

CMD ["php", "-S", "0.0.0.0:5000"]
