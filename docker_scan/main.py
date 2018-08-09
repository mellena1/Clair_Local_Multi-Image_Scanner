import os
import sys

from docker_helper import DockerHelper
import kubernetes_helper
from clair import Clair
from image_scan import ImageScan
from argparse_helper import parse_args


def main():
    # Get cmdline args
    args = parse_args()

    cfg = {}
    # docker connect
    if args.docker_connect is None:
        cfg['docker.connect'] = 'unix:///var/run/docker.sock'
    else:
        cfg['docker.connect'] = args.docker_connect
    # Clair host
    cfg['clair.host'] = 'http://127.0.0.1:6060'
    # Output dir
    if args.output_dir is None:
        output_dir = 'reports'
    else:
        output_dir = args.output_dir

    # Make objs to help with retrieving info
    docker_helper = DockerHelper(cfg['docker.connect'])
    clair_obj = Clair(cfg, docker_helper.docker_cli)

    # Source of images
    if args.source == 'docker':
        if args.docker_server is None:
            images = docker_helper.get_container_images()
        else:
            docker_server = DockerHelper(args.docker_server)
            images = docker_server.get_container_images()
    elif args.source == 'k8s' or args.source == 'kubernetes':
        images = kubernetes_helper.get_pod_images(docker_helper)
    elif args.source == 'file':
        # If specifying file, make sure it exists
        if not os.path.exists(args.file):
            print('{} does not exist!!!'.format(args.file))
            sys.exit(1)
        images = images_from_file(args.file, docker_helper)

    # Scan all images  {name:ImageScan}
    scanned_images = {}
    for image in images:
        name = get_print_tag(image)
        print('Starting scan on {}...'.format(name))
        scanned_images[name] = ImageScan(image, clair_obj)
        print('{} done'.format(name))
        if image != images[-1]:
            print('\n')

    # Make sure output dir is made
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    # Write all of the vulnerabilites to disk
    for name, imagescan in scanned_images.items():
        imagescan.write_to_file(output_dir, name)


def get_print_tag(docker_image):
    """
    get_print_tag

    :return: Either a tag of the image or 16 characters of the image hash
    """
    if len(docker_image.tags) == 0:
        return docker_image.id[:16]
    else:
        return docker_image.tags[0]


def images_from_file(filename, docker_helper):
    """
    images_from_file

    :param filename str: The path to the file
    :param docker_helper DockerHelper: The docker_helper obj to get the images
    :return: A list of docker image objects
    """
    images = []
    with open(filename, 'r') as f:
        for line in f:
            image_id = line.strip()
            i = docker_helper.get_image_obj_from_id(image_id)
            images.append(i)
    return images


if __name__ == '__main__':
    main()
