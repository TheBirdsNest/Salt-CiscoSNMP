FROM python:3.7
MAINTAINER lawrence@lawrence-bird.com

RUN apt-get update -y
RUN apt-get upgrade -y

RUN pip3 install pysnmp pysnmp-mibs

ENTRYPOINT /bin/bash
