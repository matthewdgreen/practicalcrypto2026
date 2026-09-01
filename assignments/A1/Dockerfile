# Course container for Assignment 1 builds and autograding.
#   docker build -t pcs-a1 grading/A1
# Students test with:  docker run --rm -v "$PWD":/sub -w /sub pcs-a1 bash ./build.sh
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential clang make cmake pkg-config git curl ca-certificates \
      python3 python3-pip python3-venv python3-numpy \
      golang-go rustc cargo \
      openjdk-21-jdk-headless nodejs npm \
      ruby perl \
    && rm -rf /var/lib/apt/lists/*
COPY toolchains.sh /usr/local/bin/toolchains
RUN chmod +x /usr/local/bin/toolchains
WORKDIR /sub
CMD ["bash"]
