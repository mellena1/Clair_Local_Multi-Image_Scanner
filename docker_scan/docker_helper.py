import docker


class DockerHelper:
    """
    DockerHelper

    A class to hold the DockerClient object and provide a few nice helper
    methods
    """
    docker_cli = None

    def __init__(self, docker_connect):
        """
        __init__

        Create the docker_cli object given an endpoint

        :param docker_connect str: The endpoint for docker
        """
        self.docker_cli = docker.DockerClient(base_url=docker_connect,
                                              timeout=1800)

    def get_container_images(self):
        """
        get_container_images

        :return: A list of image objects from the Docker library
        """
        images = []
        for container in self.docker_cli.containers.list():
            images.append(container.image)
        return images

    def get_image_obj_from_id(self, image_id):
        """
        get_image_obj_from_id

        :param image_id str: The image id to get a Docker Image object of
        :return: A Docker.Image object
        """
        try:
            return self.docker_cli.images.get(image_id)
        except:
            return self.docker_cli.images.pull(image_id)
