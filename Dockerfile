FROM alpine:latest

RUN apk update
RUN apk add python3
RUN apk add curl iputils
RUN apk add krb5-user
COPY pip_requirements.txt .
RUN pip3 install -r pip_requirements.txt
COPY version/VERSION /exporter/
COPY citrix-exporter.py /exporter/
COPY metrics.json /exporter/
RUN touch /exporter/exporter.log
RUN ln -sf /dev/stdout /exporter/exporter.log
USER nobody

ENTRYPOINT ["python3","/exporter/citrix-exporter.py"]