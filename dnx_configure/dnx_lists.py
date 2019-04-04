#!/usr/bin/python3

import os, json

class ListFiles:
    def __init__(self):
        self.combinefiles = []
        self.path = os.environ['HOME_DIR']

    def CombineList(self):
        with open('{}/data/categories.json'.format(self.path), 'r') as categories:
            category = json.load(categories)

        default_cats = category['DNSProxy']['Categories']['Default']
        ud_cats = category['DNSProxy']['Categories']['UserDefined']

        for cat in default_cats:
            if (default_cats[cat]['Enabled'] == 1):
                self.combinefiles.append(cat)

        with open('{}/domainlists/Blocked.domains'.format(self.path), 'w+') as Blocked:
            for files in self.combinefiles:
                with open('domainlists/{}.domains'.format(files), 'r+') as files:
                    for line in files:
                        Blocked.write(line)
            for cat in ud_cats:
                if (cat['Enabled'] == 1):
                    for entry in cat:
                        if ('Enabled' not in line):
                            Blocked.write('{} {}'.format(entry.lower(), cat.lower()))

if __name__ == '__main__':
    ListFile = ListFiles()
    ListFile.CombineList()                
