FROM ubuntu:latest
LABEL maintainer='DistriNet'
#TO RUN AND CONNECT TO THE IMAGE RUN THE FOLLOWING COMMANDS:
#docker build -t <"name">
#map the port being exposed at the bottom of this scripts to any ports of your choosing




RUN apt-get update && apt-get install --no-install-recommends --yes python3
RUN apt-get -y install git
RUN apt-get -y install python3-pip python3.12-venv


# Clone Repo..
ENV VIRTUAL_ENV=/home/ubuntu/dAngr/venv
RUN git clone https://github.com/angr-debugging/dAngr.git /home/ubuntu/dAngr
RUN python3 -m venv "$VIRTUAL_ENV"
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN cd /home/ubuntu/dAngr/ &&  pip install . && pip install setuptools

ENTRYPOINT ["sh", "-c","cd /home/ubuntu/dAngr && /home/ubuntu/dAngr/venv/bin/dAngr"]