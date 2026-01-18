FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# ---- Base dependencies ----
RUN apt update && apt install -y \
    git \
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
    sudo \
    nano \
    lsb-release \
    tcpdump \
    libffi-dev \
    libprotobuf-dev \
    protobuf-compiler \
    libtool \
    libboost-all-dev \
    && rm -rf /var/lib/apt/lists/*

# ---- Install Python deps ----
RUN pip3 install --no-cache-dir \
    psutil \
    scapy \
    thrift \
    networkx

# ---- Build BMv2 ----
WORKDIR /opt
RUN git clone https://github.com/p4lang/behavioral-model.git
WORKDIR /opt/behavioral-model
RUN ./install_deps.sh
RUN ./autogen.sh && \
    ./configure && \
    make -j$(nproc) && \
    make install && \
    ldconfig
RUN echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/bmv2.conf && \
    sudo ldconfig
# ---- Build p4c ----
WORKDIR /opt
RUN git clone https://github.com/p4lang/p4c.git
WORKDIR /opt/p4c
RUN git submodule update --init --recursive
RUN mkdir build
WORKDIR /opt/p4c/build
RUN cmake .. && \
    make -j$(nproc) && \
    make install

# ---- Default ----
RUN echo "export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH" >> ~/.bashrc
RUN echo "export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH" >> ~/.profile
RUN apt update && apt install -y netcat inetutils-ping xterm
WORKDIR /root
CMD ["/bin/bash"]
