# Clair Local Multi-Image Scanner

## What is this tool for?
This script allows you to automate security scans for multiple docker images. Clair is meant for running in a continuous integration environment, to check your Docker images when created, but this tool fulfills the use case of wanting to test all of your images that are currently running on a cluster or on a machine.

## How to run
The script provides 3 options for input. You can either provide it a file (newline delimited image tags/ids), run it against a docker server (it will check any running container), or against a kubernetes cluster (check all running pods).

* File:
    * `python docker_scan/main.py file <file-name>`
* Docker:
    * `python docker_scan/main.py docker`
* Kubernetes:
    * `python docker_scan/main.py kubernetes`

For running it against a Docker server, you also have the option of specifying the server location:
* `python docker_scan/main.py docker --docker-server "http://192.168.1.1:1234"`

For running with kubernetes, it will go to whatever kubernetes cluster is selected in your kube config (~/.kube/config).

Check the help for more options/info:

`python docker_scan/main.py -h`

or

`python docker_scan/main.py {file,docker,k8s} -h`

## Setup
For this script to work, you must have a local Clair server running. I have provided the docker-compose setup in the `clair-runner` folder to get that running. As long as you have Docker and Docker-Compose on your machine, you can run 

`docker-compose up -d`

in the `clair-runner` folder. This will start up the Clair server along with its Postgres DB. It will take about 20 minutes for Clair to get its index of information setup, so you will have to wait for that. You can use

`docker-compose down`

to take the Clair server and the DB back down.

You must also have the dependencies listed in `requirements.txt` installed. You can easily do this with

`pip install -r requirements.txt`

## Current Limitations
* Currently, the Clair server must be running locally because of how the images are checked. The images are saved locally in the tmp folder using `docker save` command, and then Clair is told to scan the image at that temporary location. Being able to use a remote Clair server would definitely be nicer.
* Because of having to save the images locally in tar files, the script takes a little bit to run with larger images. Being able to check if an image is publically available and passing that to Clair would definitely make it more ideal.
