FROM ubuntu:latest
LABEL maintainer='DistriNet'
#TO RUN AND CONNECT TO THE IMAGE RUN THE FOLLOWING COMMANDS:
#docker build -t <"name">
#map the port being exposed at the bottom of this scripts to any ports of your choosing



RUN apt-get update && apt-get install --no-install-recommends --yes python3
RUN apt-get -y install git
# Clone Repo..
RUN git clone https://github.com/angr-debugging/dAngr.git


ENTRYPOINT ["/sbin/init"]