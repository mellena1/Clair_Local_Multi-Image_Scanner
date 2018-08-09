FROM python:3.6.4

COPY requirements.txt ./
RUN pip install -r requirements.txt

RUN mkdir docker_scan
WORKDIR docker_scan

COPY docker_scan/__init__.py ./
COPY docker_scan/main.py ./
COPY docker_scan/image_scan.py \
     docker_scan/docker_helper.py \
     docker_scan/clair.py \
     docker_scan/argparse_helper.py \
     docker_scan/kubernetes_helper.py ./

ENTRYPOINT ["python", "main.py"]
