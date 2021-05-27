FROM python:2

RUN set -ex ;\
    apt-get update ;\
    apt-get install -y \
        clamav \
        clamav-daemon \
        docker.io ;\
    freshclam

RUN pip install PyYAML gitpython

COPY . /opt/clambake

WORKDIR /opt/clambake

ENV dockerServer=hub.docker.io
ENV gerritUsername=null
ENV dockerUsername=null
ENV dockerPassword=null
ENV reportDirectory=/tmp/clambake/reports
ENV tempDirectory=/tmp/clambake/temp
ENV needCleanup=False
ENV scanType=singleImage
ENV imageToScan=docker.io/libary/ubuntu:xenial

RUN set -ex ;\
    mkdir -p $reportDirectory $tempDirectory

