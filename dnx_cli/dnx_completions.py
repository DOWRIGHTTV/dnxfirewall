import os

cwords = os.environ['COMP_WORDS'].split()
cword_pos = int(os.environ['COMP_CWORD'])
cline = os.environ['COMP_LINE']

modules = 'cfirewall dns-proxy ip-proxy ids-ips dhcp-server database logging webui'
compiled_mods = 'cfirewall cprotocol-tools dnx-nfqueue hash-trie'

cmd_map = {
    'help': '',
    'start': modules,
    'restart': modules,
    'stop': modules,
    'status': modules,
    'journal': modules,
    'cli': modules,
    'install': 'system',
    'update': 'system signatures',
    'compile': compiled_mods
}

if (cword_pos == 1):

    if cmd_empty := len(cwords) == 1:
        print(' '.join(cmd_map))

    else:
        current_word = cwords[cword_pos]

        print(' '.join([c for c in cmd_map if c.startswith(current_word)]))

elif (cword_pos == 2 and cwords[1] in cmd_map):

    if mod_empty := len(cwords) == 2:
        print(cmd_map.get(cwords[1]))

    else:
        current_word = cwords[cword_pos]

        print(' '.join([m for m in cmd_map.get(cwords[1]).split() if m.startswith(current_word)]))
