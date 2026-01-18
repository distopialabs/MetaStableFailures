FROM  ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y \
    git \
    sudo \
    cmake \
    build-essential \
    automake \
    libtool \
    pkg-config \
    python3 \
    python3-pip \
    python3-setuptools \
    python3-dev \
    curl \
    wget \
    libjudy-dev \
    libgmp-dev \
    libpcap-dev \
    libboost-all-dev \
    libssl-dev \
    thrift-compiler \
    libthrift-dev \
    bison \
    flex \
    tcpdump \
    mininet \
    iproute2 \
    net-tools \
    lsb-release \
    nano \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/p4lang/behavioral-model.git /opt/bmv2
WORKDIR /opt/bmv2

RUN ./install_deps.sh
RUN ./autogen.sh && \
    ./configure && \
    make -j$(nproc) && \
    make install && \
    ldconfig

RUN echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/bmv2.conf && \
    sudo ldconfig

RUN mkdir p4-files
COPY /build /opt/bmv2/p4-files

RUN echo "export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH" >> ~/.bashrc
RUN echo "export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH" >> ~/.profile
CMD ["/bin/bash"]