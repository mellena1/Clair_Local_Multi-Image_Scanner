from kubernetes import client, config


config.load_kube_config()
v1 = client.CoreV1Api()


def get_pod_images(docker_helper):
    """
    get_pod_images

    Get all pod images

    :param docker_helper docker_helper.DockerHelper: The docker_helper obj to
        use for getting Docker.Image objects from.
    :return: The list of docker.Image objects
    """
    images = []
    ret = v1.list_pod_for_all_namespaces(watch=False)
    for i in ret.items:
        for container in i.status.container_statuses:
            image_id = container.image
            images.append(docker_helper.get_image_obj_from_id(image_id))
    return images


def ping():
    """
    ping

    ping the k8s cluster to make sure it is alive
    """
    try:
        v1.list_namespace()
    except:
        raise Exception()
