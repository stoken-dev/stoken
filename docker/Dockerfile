FROM 		ubuntu:16.04

RUN 		apt-get update
RUN 		apt-get install -y \
				libgtk-3-dev \
				libtomcrypt-dev \
				libxml2-dev \
				autoconf \
				automake \
				libtool \
				build-essential \
				git

RUN 		git clone git://github.com/cernekee/stoken

WORKDIR 	stoken

RUN 		bash autogen.sh && \
			./configure && \
			make && \
			make check && \
			make install && \
			ldconfig

CMD 		stoken
