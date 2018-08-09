# Taken a lot from https://bitbucket.org/osallou/clair.git
# That package was written for Python 2, and it uses a different docker
# library than I wanted to use. I also added some optimizations to what
# that library was doing

import os
import logging
import tempfile
import shutil
import tarfile
import json

import requests


class Clair:
    """
    Clair

    A class to make all of the Clair API calls
    """
    def __init__(self, cfg, docker_cli):
        '''
        Cfg is a dict:

            cfg = {
                'clair.host': 'http://localhost:6060',
                'docker.connect': 'tcp://127.0.0.1:2375' or None for socks.
            }
        '''
        self.cfg = cfg
        self.docker_cli = docker_cli
        # Hold onto what layers have already been analysed to reduce API calls
        # Could be useful for images that use a similar base
        # {layer_id:vulnerabilties}
        self.already_analysed = {}

    def analyse_layer(self, layer):
        """
        analyse_layer

        Send a POST to the Clair API to analyse this layer (it will be added
            to Clair's DB)

        :param layer dict: The dict of info for the API call
        """

        '''
        POST http://localhost:6060/v1/layers HTTP/1.1

            {
              "Layer": {
                "Name": "523ef1d23f222195488575f52a39c729c76a8c5630c9a194139cb246fb212da6",
                "Path": "/mnt/layers/523ef1d23f222195488575f52a39c729c76a8c5630c9a194139cb246fb212da6/layer.tar",
                "ParentName": "140f9bdfeb9784cf8730e9dab5dd12fbd704151cf555ac8cae650451794e5ac2",
                "Format": "Docker"
              }
            }
        '''
        clair_layer = {
            'Layer': {
                'Name': layer['id'],
                'Path': layer['path'],
                'ParentName': layer['parent'],
                'Format': 'Docker'
            }
        }
        r = requests.post(self.cfg['clair.host']+'/v1/layers',
                          data=json.dumps(clair_layer))
        if r.status_code != 201:
            logging.error(
                layer['image'] + ':Failed to analyse layer ' + layer['id'])

    def analyse(self, docker_image):
        """
        analyse

        Analyse a docker image by saving it locally and telling clair to check
            it. Currently this only works if Clair is running on the same
            machine as the script is run on.

        :param docker_image docker.Image: The docker Image object to analyse
        :return: The layers in this image that were analysed
        """
        image = docker_image.id
        (image_tar, tmp_path) = tempfile.mkstemp(suffix="-bioshadock-image")

        # Make tar of docker image
        file_tar = open(tmp_path, 'wb')
        for data in docker_image.save():
            file_tar.write(data)
        file_tar.close()

        # Untar the image
        tmp_dir = tempfile.mkdtemp(suffix='-bioshadock-image-archive')
        image_archive = tarfile.TarFile(name=tmp_path)
        image_archive.extractall(path=tmp_dir)
        image_archive.close()

        # Read the layer manifest to create all of the layer dicts for API
        # calls
        layers = []
        with open(os.path.join(tmp_dir, 'manifest.json'), 'r') as content_file:
            content = content_file.read()
            manifest = json.loads(content)
            logging.debug(str(manifest))
            parent_layer = ""
            for layer in manifest[0]['Layers']:
                layers.append({'id': layer.replace('/layer.tar', ''),
                               'path': os.path.join(tmp_dir, layer),
                               'parent': parent_layer,
                               'image': image
                               })
                parent_layer = layer.replace('/layer.tar', '')

        # Tell clair to analyse the layers
        for layer in layers:
            # Don't do the analyse if it already has been analysed
            # (minimize API calls)
            if layer['id'] not in self.already_analysed:
                self.analyse_layer(layer)

        # Get rid of the tmp stuff
        os.remove(tmp_path)
        shutil.rmtree(tmp_dir)
        return layers

    def get_layers_vulnerabilities(self, layer_ids):
        """
        get_layers_vulnerabilities

        :param layer_ids list: All of the layers to get vulns for
        :return: All of the vulnerabilites for a list of layers
        """
        vulnerabilities = []
        for layer_id in layer_ids:
            # Check if this layer has been analysed already
            if layer_id in self.already_analysed:
                # Only add it to the list if it has a response
                if self.already_analysed[layer_id] is not None:
                    vulnerabilities.append(self.already_analysed[layer_id])
                    continue
            # If not, go grab it from clair
            layer_vulnerabilities = self.get_layer_vulnerabilities(layer_id)
            # Don't add if there was an error
            if layer_vulnerabilities is not None:
                vulnerabilities.append(layer_vulnerabilities)
            # Add it to the already_analysed dict
            self.already_analysed[layer_id] = layer_vulnerabilities
        return vulnerabilities

    def get_layer_vulnerabilities(self, layer_id):
        """
        get_layer_vulnerabilities

        Make an API call to get the vulnerabilites for a layer

        :param layer_id str: The layer_id of the layer
        :return: The json response from the call
        """

        '''
        GET http://localhost:6060/v1/layers/17675ec01494d651e1ccf81dc9cf63959ebfeed4f978fddb1666b6ead008ed52?features&vulnerabilities
        '''
        r = requests.get(self.cfg['clair.host']+'/v1/layers/'+layer_id+'?features&vulnerabilities')
        if r.status_code != 200:
            logging.error('Could not get info on layer '+layer_id)
            return None
        return r.json()
