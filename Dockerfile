FROM ubuntu:latest

RUN apt update
RUN apt install python3 curl iputils* krb5-user -y
COPY pip-requirements.txt .
RUN pip3 install -r pip-requirements.txt
COPY version/VERSION /exporter/
COPY citrix-exporter.py /exporter/
COPY metrics.json /exporter/
RUN touch /exporter/exporter.log
RUN ln -sf /dev/stdout /exporter/exporter.log
USER nobody

ENTRYPOINT ["python3","/exporter/citrix-exporter.py"]