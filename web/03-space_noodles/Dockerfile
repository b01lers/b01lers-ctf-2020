FROM python:3.7-alpine
RUN pip3 --no-cache-dir install flask

RUN mkdir server_files
RUN mkdir /server_files/logs

COPY static /server_files/static
COPY templates /server_files/templates
COPY server.py /server_files

RUN chown nobody:nogroup /server_files
USER nobody
WORKDIR /server_files

CMD ["python3", "server.py"]
