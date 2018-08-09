all:
	make build
	make run

build:
	docker build -t cybersec-final:latest .

run:
	docker run --rm \
	-v /var/run/docker.sock:/var/run/docker.sock \
	-v ~/.kube:/root/.kube \
	-v /tmp:/tmp \
	--net="host" \
	cybersec-final:latest docker

start-clair:
	cd clair-runner && docker-compose up -d

stop-clair:
	cd clair-runner && docker-compose down
