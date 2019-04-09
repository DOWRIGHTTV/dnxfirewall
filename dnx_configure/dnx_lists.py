#!/usr/bin/python3

import os, json

class ListFiles:
    def __init__(self):
        self.combinefiles = []
        self.path = os.environ['HOME_DIR']

        with open('{}/data/categories.json'.format(self.path), 'r') as categories:
            self.category = json.load(categories)

    def CombineLists(self):

        default_cats = self.category['DNSProxy']['Categories']['Default']

        for cat in default_cats:
            if (default_cats[cat]['Enabled'] == 1):
                self.combinefiles.append(cat)

        with open('{}/dnx_domainlists/blocked.domains'.format(self.path), 'w+') as blocked:
            for files in self.combinefiles:
                with open('{}/dnx_domainlists/{}.domains'.format(self.path, files.lower()), 'r+') as files:
                    for line in files:
                        if ('#' not in line):
                            blocked.write(line)
                            
if __name__ == '__main__':
    ListFile = ListFiles()
    ListFile.CombineLists()                
