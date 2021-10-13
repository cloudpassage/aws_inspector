FROM docker.io/halotools/python-sdk:ubuntu-18.04_sdk-latest_py-3.6

WORKDIR /app/

COPY ./ /app/

RUN pip3 install -r /app/requirements.txt

CMD /usr/bin/python3 /app/application.py