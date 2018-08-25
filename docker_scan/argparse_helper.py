import argparse


def parse_args():
    """
    Parse args from the command line

    :returns: The args object containing the arguments.
    """
    parser = argparse.ArgumentParser(
                    description=('Security check multiple docker images'
                                 ' using clair')
    )

    # Main optional args
    parser.add_argument('-o', '--output-dir',
                        help=('The output folder. Where to store all of the'
                              ' vulnerability reports. Defaults to ./reports'),
                        type=str)
    parser.add_argument('--docker-connect',
                        help=('Specify the ip/port of the docker server to'
                              ' use for storing temporary images. Will default'
                              ' to unix:///var/run/docker.sock'),
                        type=str)

    # Add subparsers (one of these must be specified)
    subparsers = parser.add_subparsers(dest='source', help='sub-command help')
    subparsers.required = True
    file_parser(subparsers)
    docker_parser(subparsers)
    k8s_parser(subparsers)
    return parser.parse_args()


def file_parser(subparsers):
    """
    file_parser

    Add the file subparser to the subparsers

    :param subparsers: The subparsers list to add the parser to
    """
    parser = subparsers.add_parser(
                    'file',
                    description=('Security check images from a list of images')
    )
    parser.add_argument('filepath',
                        help=('The file to read in.'
                              ' Should be a newline separated list.'),
                        type=str)


def docker_parser(subparsers):
    """
    docker_parser

    Add the docker subparser to the subparsers

    :param subparsers: The subparsers list to add the parser to
    """
    parser = subparsers.add_parser(
                    'docker',
                    description=('Security check images from the running'
                                 ' containers on a docker server.')
    )
    parser.add_argument('--docker-server',
                        help=('The docker server to get the running containers'
                              ' from. Defaults to'
                              ' unix:///var/run/docker.sock'),
                        type=str, default='unix:///var/run/docker.sock')


def k8s_parser(subparsers):
    """
    k8s_parser

    Add the kubernetes/k8s subparser to the subparsers

    :param subparsers: The subparsers list to add the parser to
    """
    subparsers.add_parser(
                    'kubernetes', aliases=['k8s'],
                    description=('Security check images from the running'
                                 ' pods on a kubernetes cluster.')
    )
