FROM ubuntu:latest
#TO RUN AND CONNECT TO THE IMAGE RUN THE FOLLOWING COMMANDS:
#docker build -t <"name">
#map the port being exposed at the bottom of this scripts to any ports of your choosing

RUN apt-get update
RUN apt-get install --no-install-recommends --yes python3
RUN apt-get -y install git
RUN apt-get -y install python3-pip 
RUN apt-get -y install python3.12-venv 
RUN apt-get -y install graphviz 
RUN apt-get -y install graphviz-dev
RUN apt-get -y install nettools

# Setup environment
ENV VIRTUAL_ENV=/home/ubuntu/venv
RUN python3 -m venv "$VIRTUAL_ENV"
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
# Clone Repo..
ARG CASH=1
ADD . /home/ubuntu/dAngr
# Install dAngr
ENV BUILD_TYPE=Release
RUN  cd /home/ubuntu/dAngr/ && pip install .
WORKDIR /workspace
ENTRYPOINT ["dAngr"]
