from kubernetes import client, config


class KubernetesHelper:
    """
    KubernetesHelper

    A class to hold a kubernetes connection object
    """
    def __init__(self):
        """
        Creates a KubernetesHelper object. Will raise an exception if reading
        the kubernters config file fails.
        """
        try:
            config.load_kube_config()
        except Exception as ex:
            print(ex)
            print(('Error loading kubernetes config. Please verify'
                   ' that it is setup correctly.'))
            raise ex
        self.v1 = client.CoreV1Api()
        self.host = self.v1.api_client.configuration.host

    def get_pod_images(self, docker_helper):
        """
        get_pod_images

        Get all pod images

        :param docker_helper docker_helper.DockerHelper: The docker_helper obj
            to use for getting Docker Image objects from.
        :return: The list of docker.Image objects
        """
        images = []
        ret = self.v1.list_pod_for_all_namespaces(watch=False)
        for i in ret.items:
            for container in i.status.container_statuses:
                image_id = container.image
                images.append(docker_helper.get_image_obj_from_id(image_id))
        return images

    def ping(self):
        """
        ping

        ping the k8s cluster to make sure it is alive
        """
        self.v1.list_namespace()
