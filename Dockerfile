FROM reg.lily.kazv.moe/kazv/libkazv-deps/deps:servant

RUN mkdir -pv /build
COPY . /build/libkazv

WORKDIR /build/libkazv

ARG BUILD_TYPE=Debug
ARG JOBS=3

ARG DEPS_INSTALL_DIR=/opt/libkazv-deps
ARG LIBKAZV_INSTALL_DIR=/opt/libkazv

RUN mkdir build && cd build && \
    export CC=gcc-9 CXX=g++-9 && \
    cmake .. -DCMAKE_INSTALL_PREFIX="$LIBKAZV_INSTALL_DIR" -DCMAKE_PREFIX_PATH="$DEPS_INSTALL_DIR" -DCMAKE_BUILD_TYPE=$BUILD_TYPE -Dlibkazv_BUILD_TESTS=OFF -Dlibkazv_BUILD_EXAMPLES=ON -Dlibkazv_BUILD_KAZVJOB=ON && \
    make -j$JOBS && \
    make -j$JOBS install 
