FROM ubuntu:latest

RUN apt update -qq
ENV DEBIAN_FRONTEND=noninteractive
RUN apt install python3 python3-pip curl iputils* krb5-user -yqq
COPY pip-requirements.txt .
RUN pip3 install -r pip-requirements.txt
COPY citrix-exporter.py /exporter/
COPY metrics.json /exporter/
RUN touch /exporter/exporter.log
RUN ln -sf /dev/stdout /exporter/exporter.log
USER nobody

ENTRYPOINT ["python3","/exporter/citrix-exporter.py"]