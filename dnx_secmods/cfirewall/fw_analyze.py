#!/usr/bin/env python3

from dnx_gentools.file_operations import ConfigurationManager, ConfigChain, load_data

from dnx_secmods.cfirewall.fw_control import *

def diff():
    with ConfigurationManager(DEFAULT_VERSION, ext='firewall', file_path=DEFAULT_PATH) as dnx_fw:
        pending: ConfigChain = dnx_fw.load_configuration()

        pending_rules = pending.get_dict()

        convert_ruleset(FirewallControl.sections, pending_rules, name_only=True)

        # temporarily restricting to main set
        pending_rules = pending_rules['MAIN']

        # if active copy is not present, then rules have not been pushed before so all rules will be in diff
        try:
            active_rules = load_data('active_copy.firewall', filepath=f'{DEFAULT_PATH}/usr')
        except FileNotFoundError:
            active_rules = {'BEFORE': {}, 'MAIN': {}, 'AFTER': {}}

        convert_ruleset(FirewallControl.sections, active_rules, name_only=True)

        # temporarily restricting to main set
        active_rules = active_rules['MAIN']

        # swapping POS and ID. diff based on ID will be more accurate, detailed, and effective.
        p_rules, a_rules = {}, {}
        for pos, rule in pending_rules.items():
            rid = rule.pop('id')
            rule['pos'] = pos

            p_rules[rid] = rule

        for pos, rule in active_rules.items():
            rid = rule.pop('id')
            rule['pos'] = pos

            a_rules[rid] = rule

    p_rules_set = set(p_rules)
    a_rules_set = set(a_rules)

    change_list = {'added': [], 'removed': [], 'modified': []}

    for rule in p_rules_set - a_rules_set:
        change_list['added'].append(['add', p_rules[rule]['name']])

    for rule in a_rules_set - p_rules_set:
        change_list['removed'].append(['rem', a_rules[rule]['name']])

    for rule in a_rules_set & p_rules_set:

        a_rule = a_rules[rule]
        p_rule = p_rules[rule]

        # rule definition has not changed
        if (a_rule == p_rule): continue

        rule_mods = [a_rule['name']]

        for (a_k, a_v), (p_k, p_v) in zip(a_rule.items(), p_rule.items()):

            # rule field has not changed
            if (a_v == p_v): continue

            # code, name, old setting, new setting
            rule_mods.append(['mod', a_k, a_v, p_v])

        change_list['modified'].append(rule_mods)

    return change_list
