import os
from prettytable import PrettyTable


class ImageScan:
    """
    ImageScan

    A class to hold an image and its vulnerabilites
    """
    def __init__(self, image, clair_obj):
        """
        __init__

        Get an image and figure out its vulnerabilites

        :param image docker.Image: A docker Image object
        :param clair_obj clair.Clair: A Clair object to get the vulnerability
            objects from
        """
        self.image = image
        self.vulnerabilites = self.__get_vulnerabilites(clair_obj)

    def get_vulnerabilites(self):
        """
        get_vulnerabilites

        Method to return the vulnerabilites

        :return: The vulnerabilites data structure
        """
        return self.vulnerabilites

    def __get_vulnerabilites(self, clair_obj):
        """
        __get_vulnerabilites

        Analyse this image and return the vulnerabilites list

        :param clair_obj Clair: The clair object to use for the analysis
        :return: The huge fun data structure that clair returns
        """
        layers = clair_obj.analyse(self.image)
        layer_ids = []
        for layer in layers:
            layer_ids.append(layer['id'])
        return clair_obj.get_layers_vulnerabilities(layer_ids)

    def write_to_file(self, folder, filename):
        """
        write_to_file

        Write the data about this image to a file. Formats it by separating
        each layer into its own vulnerability table.

        :param folder str: The folder location to write to
        :param filename str: What to name this file
        """
        filename = filename.replace('/', '-')
        filename = filename.replace(':', '.') + '.txt'
        full_path = os.path.join(folder, filename)

        layers_to_write = {}  # {layer-name:table}

        headers = ['Name', 'Version', 'Format', 'Vulnerability', 'Severity',
                   'Link', 'Description']
        blank_row = [('-'*10)]*len(headers)  # A row of all dashes
        no_vulns = ['No', 'Known', 'Vulnerabilites']  # No known vulns text
        # A row to add to the table if a layer has no known vulns
        no_vulns_row = no_vulns + [blank_row[0]] + no_vulns

        # Go through all of the layers to create tables for each layer
        for layer in self.vulnerabilites:
            layer = layer['Layer']  # The dict is setup weird
            layer_name = layer['Name']
            t = PrettyTable(headers)  # The table for this layer

            # Make sure the layer has features
            if 'Features' not in layer:
                layers_to_write[layer_name] = t
                continue
            # Make feature objects for this layer
            feature_objs = []
            for feature in layer['Features']:
                # Ignore the feature if it doesn't have vulnerabilites
                if 'Vulnerabilities' not in feature:
                    continue
                # Also ignore if it wasn't added by this layer
                if 'AddedBy' in feature and feature['AddedBy'] != layer_name:
                    continue
                feature_objs.append(_Feature(feature))
            # Sort the feature_objs based on severity of the feature
            feature_objs.sort(reverse=True)

            # Add all of the features to the table
            for feature_obj in feature_objs:
                for row in feature_obj.rows:
                    t.add_row(row)
                t.add_row(blank_row)
            # Add table to layers to write
            layers_to_write[layer_name] = t

        # Write the tables to the file
        with open(full_path, 'w') as f:
            for name, layer_table in layers_to_write.items():
                f.write('Layer: ' + name + '\n')
                if len(layer_table._rows) == 0:
                    layer_table.add_row(no_vulns_row)
                f.write(str(layer_table) + '\n\n')


class _Feature:
    """
    _Feature

    A class to hold features that have Vulnerabilites
    """
    def __init__(self, feature_dict):
        """
        __init__

        :param feature_dict dict: A feature dict from the vulnerabilites info
            from clair. Assumes that this dict has Vulnerabilites.
        """
        self.name = feature_dict['Name']
        self.version = feature_dict['Version']
        self.version_format = feature_dict['VersionFormat']
        self.vulns = []  # List of _Vulnerability objects
        for vuln in feature_dict['Vulnerabilities']:
            self.vulns.append(_Vulnerability(vuln))
        # Sort the vulnerabilites in order from highest severity to lowest
        self.vulns.sort(reverse=True)
        # Make the rows and give this feature a severity value
        self.rows = self._make_rows()
        self.sev_val = self._get_total_sev_val()

    def _make_rows(self):
        """
        _make_rows

        :return: The rows for the table for this feature. Will be sorted from
            highest severity to lowest severity (unknown, high, medium, low,
            negligible)
        """
        rows = []
        for index, vuln in enumerate(self.vulns):
            row = []
            if index == 0:
                row.extend([self.name, self.version, self.version_format])
            else:
                row.extend(['', '', ''])
            row.extend([vuln.name, vuln.severity, vuln.link, vuln.description])
            rows.append(row)
        return rows

    def _get_total_sev_val(self):
        """
        _get_total_sev_val

        :return: The total severity value for this feature. The formula for a
            feature's severity value is the sum of each of its vulnerability's
            sev_vals.
        """
        return sum(x.sev_val for x in self.vulns)

    def __lt__(self, y):
        """
        __lt__

        :return: True if self is less important than y. Importance is judged
            by having the highest sev_val (have a bunch of severe vulns)
        """
        return self.sev_val < y.sev_val


class _Vulnerability:
    """
    _Vulnerability

    A class to hold info about a vulnerability
    """
    # Severity with highest value is most important
    sev_vals = {'Unknown': 4,
                'High': 3,
                'Medium': 2,
                'Low': 1,
                'Negligible': 0}

    def __init__(self, vuln_dict):
        """
        __init__

        Extracts data from the vuln_dict and stores it
        """
        self.name = vuln_dict['Name']
        self.severity = vuln_dict['Severity']
        self.sev_val = self.sev_vals[self.severity]
        self.link = vuln_dict['Link']
        if 'Description' in vuln_dict:
            desc = vuln_dict['Description']
            if len(desc) > 40:
                desc = desc[:40]
            self.description = desc
        else:
            self.description = ''

    def __lt__(self, y):
        """
        __lt__

        :return: True if self is less severe than y
        """
        return self.sev_val < y.sev_val
