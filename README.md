# Vulnerable Flask Web Application
Vulnerable Flask Application repurposed for CTF usage (previously used in Kernelcon 2022). Caution: here be dragons (and bad, unsupported code)!

## Prerequisites
The following will need to be installed prior to running:
* Python 3 and Pip
* ```pip3 install -r requirements.txt```

## Docker
To build the Docker image using the Dockerfile:
```docker build -t flask-ctf:latest .```

To run in Docker:
```docker run -d --name flask-ctf --restart=always -p 8080:8080 flask-ctf```

## Warning!
DO NOT EXPOSE THIS APP PUBLICALLY ON THE INTERNET!! THIS COULD RESULT IN YOUR MACHINE OR NETWORK BECOMING COMPROMISED!!!

## Deployment
This application will listen on port 8080. To run the server, run this command in the root directory of the web application (if not using Docker):
```
python3 flaskApp.py

```
## Objectives
### Locate the flags by:
* Command Injection
* Enumerating users
* Discovering bad password usage and storage
* Privilege Escalation (to "HR" role)
* Cookie abuse for ```/better-login-demo``` endpoint

*Flags are in the format of kernel{md5_hash}*

## Disclaimer
*You are responsible for your machine(s) running this application. There are not any warranties or guarantees, written or implied, in the distribution of this software. I am not responsible for any destruction or loss of property by, or for using this vulnerable software.*
