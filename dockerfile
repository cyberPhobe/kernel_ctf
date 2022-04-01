FROM python:alpine3.7

COPY . /flask-ctf
RUN pip3 install -r /flask-ctf/requirements.txt

EXPOSE 8080
WORKDIR /flask-ctf
ENTRYPOINT [ "python3" ]
CMD [ "flaskApp.py" ]
