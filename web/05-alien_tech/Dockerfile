FROM ubuntu:16.04
# Install emsdk
RUN apt-get update -y \
        && apt-get upgrade -y \
        && apt-get install -y python tar xz-utils cmake default-jre git-core lbzip2

# Get the emsdk repo
RUN git clone https://github.com/emscripten-core/emsdk.git \
        && cd emsdk \
        && git pull \
        && ./emsdk install latest \
        && ./emsdk activate latest \
        && ./emsdk_env.sh

# Set up EMSDK environment
ENV PATH=/emsdk:$PATH
ENV PATH=/emsdk/upstream/emscripten:$PATH
ENV PATH=/emsdk/node/12.9.1_64bit/bin:$PATH

ENV EMSDK=/emsdk
ENV EM_CONFIG=/root/.emscripten
ENV EMSDK_NODE=/emsdk/node/12.9.1_64bit/bin/node

RUN mkdir server_files
WORKDIR /server_files

# Compile
COPY alien_tech.c .
RUN emcc -o alien_tech.js alien_tech.c
COPY package.json package-lock.json ./
RUN npm install

COPY auth.txt server.js ./
COPY templates templates/

RUN chown nobody:nogroup /server_files
USER nobody

CMD ["node", "server.js"]
