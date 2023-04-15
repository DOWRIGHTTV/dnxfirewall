#!/usr/bin/env python3

from __future__ import annotations

from enum import Enum
from typing import NamedTuple
from collections import defaultdict
from itertools import groupby, count
from ipaddress import IPv4Address, IPv4Network

from dnx_gentools.file_operations import ConfigurationManager, load_data, calculate_file_hash

from dnx_secmods.cfirewall.fw_control import *

from typing import TYPE_CHECKING
if (TYPE_CHECKING):
    from typing import Union, TypeAlias

    ADDRESS_OBJECTS: TypeAlias = Union[IPv4Address, IPv4Network]


__all__ = ('FirewallAnalyze',)

ANY_ZONE = 99

# FIREWALL_RULE = namedtuple('firewall_rule', 'pos action src_zone src_net src_svc dst_zone dst_net dst_svc')
class FIREWALL_RULE(NamedTuple):
    pos:    int
    action: int
    src_zone: set[int]
    src_net:  set[ADDRESS_OBJECTS]
    src_svc:  defaultdict[int, set[int]]
    dst_zone: set[int]
    dst_net:  set[ADDRESS_OBJECTS]
    dst_svc:  defaultdict[int, set[int]]

# SHADOW_RULE = namedtuple('shadow_rule', 'pos action dup_nets cmn_svcs')
class SHADOW_RULE(NamedTuple):
    pos: int
    action: int
    dup_nets: defaultdict[str, list[ADDRESS_OBJECTS]]
    cmn_svcs: dict[str, dict[int, list[str]]]

# TRAFFIC_FLOW = namedtuple('traffic_flow', 'src_zone src_net src_svc dst_zone dst_net dst_svc')
class TRAFFIC_FLOW(NamedTuple):
    src_zone: int
    src_net: IPv4Address
    src_svc: tuple[int, int]
    dst_zone: int
    dst_net: IPv4Address
    dst_svc: tuple[int, int]

class ACTION(Enum):
    NOT_DECIDED = -1
    REMOVE = 0
    ADD    = 1
    MERGE  = 2

    # do we need move?
    MOVE   = 100

def port_to_range(ports: set) -> list[str]:
    ports_list = sorted(list(ports))

    groups = groupby(ports_list, key=lambda item, c=count(): item - next(c))

    return [f'{g[0]}' if len(g) == 1 else f'{g[0]}-{g[-1]}' for g in [list(group) for k, group in groups]]

def range_to_port(ranges: list[str]) -> set:
    ports = set()

    for ran in ranges:

        r = [int(x) for x in ran.split('-')]
        if (len(r) == 1):
            ports.add(r[0])

        ports.update(range(r[0], r[1] + 1))

    return ports

def _pos_to_id(src_dict: dict) -> dict:
    converted_dict = {}

    for section in FirewallControl.sections:

        converted_dict[section] = {}

        for pos, rule in src_dict[section].items():
            rid = rule.pop('id')
            rule['pos'] = pos

            converted_dict[section][rid] = rule

    return converted_dict


class FirewallAnalyze:

    cfirewall_analyze: FirewallAnalyze

    def __init__(self):

        self.pending_hash = ''
        self.pending_rules = {'BEFORE': {}, 'MAIN': {}, 'AFTER': {}}

        self.active_hash = ''
        self.active_rules = {'BEFORE': {}, 'MAIN': {}, 'AFTER': {}}

        # ====================================
        #  WORK IN PROGRESS
        self.loaded_fw_rules = {'BEFORE': {}, 'MAIN': {}, 'AFTER': {}}
        # self.loaded_fw_rules = load_data('usr/active.firewall', filepath=DEFAULT_PATH)

        self.firewall_rules: dict[str, FIREWALL_RULE] = {}

        # position protocol/service
        self.drop_rules = {}

        # calling function to convert rules to python objects
        # self._format_ruleset()

        # for multiple operations on the identified shadow rules
        self.shadow_rule_map: dict[str, list[SHADOW_RULE]] = {}

        # converts an index/pos to a rule name (can prob remove this as being necessary)
        self.rules_idx_to_name = ['N/A', *list(self.firewall_rules)]
        # ====================================

    # todo: make this go through nat table before checking rules and specify if a nat rule would change the packet
    def check_flow(self, flow: TRAFFIC_FLOW):
        '''check for traffic flow match.

        returns the rule position and name if a matching rule is found.
        '''
        # TRAFFIC_FLOW = namedtuple('traffic_flow', 'zone_in zone_out src dst service')

        for name, fw_rule in self.firewall_rules.items():

            # zone match
            if (flow.src_zone not in fw_rule.src_zone and fw_rule.src_zone != ANY_ZONE):
                continue

            if (flow.dst_zone not in fw_rule.dst_zone and fw_rule.dst_zone != ANY_ZONE):
                continue

            # service check eg. tcp/1477 > (6, 1447)
            try:
                if (flow.src_svc[1] not in fw_rule.src_svc[flow.src_svc[0]]):
                    continue
            except:
                continue  # todo: check any protocol

            try:
                if (flow.dst_svc[1] not in fw_rule.dst_svc[flow.dst_svc[0]]):
                    continue
            except:
                continue  # todo: check any protocol

            for net in fw_rule.src_net:
                if (flow.src_net == net or flow.src_net in net):
                    break
            else:
                continue

            # dst check
            for net in fw_rule.dst_net:
                if (flow.dst_net == net or flow.dst_net in net):
                    break
            else:
                continue

            return fw_rule.pos, name

        return 0, ''

    # todo: separate file loading into separate function, considering using context manager so we can have it check
    #   before any call to analyze methods
    def diff(self):
        with ConfigurationManager(DEFAULT_VERSION, ext='firewall', file_path=DEFAULT_PATH) as dnx_fw:

            pending_hash = calculate_file_hash(PENDING_RULE_FILE, full_path=True)
            if (pending_hash != self.pending_hash):

                pending_rules = dnx_fw.load_configuration().get_dict()

                convert_ruleset(FirewallControl.sections, pending_rules, name_only=True)

                self.pending_rules = _pos_to_id(pending_rules)

            active_hash = calculate_file_hash(ACTIVE_RULE_FILE, full_path=True)
            if (active_hash != self.active_hash):

                active_rules = load_data('active_copy.firewall', filepath=f'{DEFAULT_PATH}/usr')

                convert_ruleset(FirewallControl.sections, active_rules, name_only=True)

                self.active_rules = _pos_to_id(active_rules)

        ct = ['add', 'rem', 'mod']
        change_list = {
            'BEFORE': {t: [] for t in ct}, 'MAIN': {t: [] for t in ct}, 'AFTER': {t: [] for t in ct}
        }

        for section in FirewallControl.sections:

            p_rules_set = set(self.pending_rules[section])
            a_rules_set = set(self.active_rules[section])

            for rule in p_rules_set - a_rules_set:
                change_list[section]['add'].append(list(self.pending_rules[section][rule].items()))

            for rule in a_rules_set - p_rules_set:
                change_list[section]['rem'].append(list(self.active_rules[section][rule].items()))

            for rule in p_rules_set & a_rules_set:

                p_rule = self.pending_rules[section][rule]
                a_rule = self.active_rules[section][rule]

                # rule definition has not changed
                if (a_rule == p_rule): continue

                rule_mods = [a_rule['name']]

                for (a_k, a_v), (p_k, p_v) in zip(a_rule.items(), p_rule.items()):

                    # rule field has not changed
                    if (a_v == p_v): continue

                    # note: currently treating all changes as "modified". will make it more specific later.
                    # code, name, old setting, new setting
                    rule_mods.append(['mod', a_k, a_v, p_v])

                change_list[section]['mod'].append(rule_mods)

        return change_list

    def build_shadow_map(self):
        shadow_map = {}
        for name in self.firewall_rules:
            try:
                result = self._shadower_search(name)
            except Exception as E:
                pass
            else:
                shadow_map[name] = result

        # quicker to use local data structure then assign as class object after
        self.shadow_rule_map = shadow_map

    def resolve_conflicts(self):
        # basic error handling to ensure this method isnt ran before its dependencies
        if (not self.shadow_rule_map):
            raise RuntimeError('shadow rule map must be built before conflicts can be resolved')

        decisions = []
        for name, shadowed_list in self.shadow_rule_map.items():
            # default dict will create empty lists
            if (not shadowed_list):
                continue

            shadower = self.firewall_rules.get(name)

            for shadow_info in shadowed_list:

                s_name = self.rules_idx_to_name[shadow_info.pos]
                shadowed = self.firewall_rules.get(s_name)

                # ensures a recommendation isn't provided for rules with differing actions
                if (shadowed.action != shadower.action):
                    continue

                shadowed_unique_nets = [
                    shadowed.src_net - shadower.src_net,
                    shadowed.dst_net - shadower.dst_net
                ]

                # rule is safe to merge into shadower (covers exact duplicates also)
                # this would be effectively deleting the lower (shadowed) rule.
                if not any(shadowed_unique_nets):
                    decisions.append((shadower.pos, name, ACTION.MERGE, shadow_info.pos))

                else:
                    net_containment = [True, True]
                    for i, unique_nets in enumerate(shadowed_unique_nets):

                        shadower_net = shadower.src_net if i == 0 else shadower.dst_net

                        for unique_net in unique_nets:

                            # quickly check if all unique networks are within a shadower network
                            for shadowed_net in shadower_net:
                                try:
                                    if (shadowed_net not in unique_net):
                                        break
                                except TypeError:
                                    if (unique_net != shadowed_net):
                                        break
                            else:
                                net_containment[i] = False

                    # if all unique networks fall within a shadower network, the rule is safe to merge.
                    # NOTE: merging should be the best option here. we could look for unique services, but then we would
                    # have to essentially duplicate the shadow minus the service if we want to retain coverage.
                    # todo: this could be a problem if a "drop" rule is between the two so should be checked in addition
                    if all(net_containment):
                        decisions.append((shadower.pos, name, ACTION.MERGE, shadow_info.pos))

                        # protecting the code below and will return to checking the next rule.
                        continue

                    shadow_ucs = {
                        proto: shadowed.src_svc[proto] - shadower.src_svc[proto] for proto in [1, 6, 17]
                    }
                    shadow_uds = {
                        proto: shadowed.dst_svc[proto] - shadower.dst_svc[proto] for proto in [1, 6, 17]
                    }

                    has_unique_src = any(shadow_ucs.values())
                    has_unique_dst = any(shadow_uds.values())

                    if (has_unique_src and not has_unique_dst):
                        decisions.append((shadower.pos, name, ACTION.NOT_DECIDED, shadowed.pos))

                    elif (has_unique_dst and not has_unique_src):
                        decisions.append((shadower.pos, name, ACTION.NOT_DECIDED, shadowed.pos))

                    # technically additional access could be opened if src and dst had unique nets, so we will ensure
                    # only one side of networks has uniques. note: this is also currently protected by the initial
                    # net containment condition, but that could change at a later time.
                    elif not all(net_containment):
                        decisions.append((shadower.pos, name, ACTION.MERGE, shadowed.pos))

                    else:
                        pass

    def _format_ruleset(self):
        firewall_rules = list(self.loaded_fw_rules['MAIN'].values())

        for pos, rule in enumerate(firewall_rules, 1):

            # separating all the ip networks, defining as ipaddress object and storing them in a list
            for field in ['src_network', 'dst_network']:
                # splitting on the delimiter (;)
                networks = rule[field]

                nets = set()
                # if / is in str it is a network, else it is a host | any will be converted to quad zeros
                for net in networks:
                    if (net[0] == 1):
                        nets.add(IPv4Address(net[1]))

                    elif (net[0] == 2):
                        nets.add(IPv4Network((net[1], str(IPv4Address(net[2])))))

                    # temporary handle of geolocation object
                    elif (net[0] == 6):
                        nets.add(IPv4Address(net[1]))

                # replacing original string with ipaddress object list
                rule[field] = nets

            for field in ['src_service', 'dst_service']:

                services = rule[field]

                svcs = defaultdict(set)
                for service in services:
                    # single service port
                    if (service[0] == 1):
                        svcs[service[1]].add(service[2])

                    # service range
                    elif (service[0] == 2):
                        for port in range(service[2], service[3] + 1):
                            svcs[service[1]].add(port)

                    # service list
                    elif (service[0] == 3):
                        for obj in service[1:]:
                            svcs[obj[0]].add(obj[1])

                # replacing original string with service dict
                rule[field] = svcs

            rule_name = rule['name'].lower()
            while rule_name in self.firewall_rules:
                rule_name += '_2'

            firewall_rule = FIREWALL_RULE(pos, rule['action'],
                set(rule['src_zone']), rule['src_network'], rule['src_service'],
                set(rule['dst_zone']), rule['dst_network'], rule['dst_service']
            )

            # namedtuple('firewall_rule', 'pos zone_in sources zone_out destinations service action')
            self.firewall_rules[rule_name] = firewall_rule

            # identifying any non allow rules for reference
            if (not rule['action']):
                self.drop_rules[rule_name] = pos

    def _shadower_search(self, rule_name: str, *, og_pos=None, new_pos=None) -> list[SHADOW_RULE]:
        shadow_rule_results = []

        # grabbing actual rule based on name
        # todo: why not just send the rule in directly?
        rule_being_checked = self.firewall_rules.get(rule_name)

        for name, fw_rule in self.firewall_rules.items():

            if (fw_rule.pos <= rule_being_checked.pos):
                continue

            # zone match
            if (not (rule_being_checked.src_zone & fw_rule.src_zone) and fw_rule.src_zone != ANY_ZONE):
                continue

            if (not (rule_being_checked.dst_zone & fw_rule.dst_zone) and fw_rule.dst_zone != ANY_ZONE):
                continue

            common_src_services = {
                proto: service & fw_rule.src_svc[proto] for proto, service in rule_being_checked.src_svc.items()
            }
            if (not common_src_services):
                continue

            common_dst_services = {
                proto: service & fw_rule.dst_svc[proto] for proto, service in rule_being_checked.dst_svc.items()
            }
            if (not common_dst_services):
                continue

            # src/dst ip overlap

            duplicate_networks: defaultdict[str, list[ADDRESS_OBJECTS]] = defaultdict(list)

            # iter over string to dynamically grab needed objects
            for t_ip in ['src_net', 'dst_net']:

                # dynamically grabbing rule object
                fw_nets: set[ADDRESS_OBJECTS] = getattr(fw_rule, t_ip)
                sl_nets: set[ADDRESS_OBJECTS] = getattr(rule_being_checked, t_ip)

                # iter over fw rule source list
                for fw_net in fw_nets:
                    # iter over selected rule src list | will check if any are contained within the above network
                    for sel_net in sl_nets:
                        try:  # TODO: make this better than wrapping entire if block
                            if (fw_net == sel_net):
                                duplicate_networks[t_ip].append(fw_net)

                            # NOTE: currently protected by try block. if ipv4address causes error on method call
                            # then that means it cannot be a subnet of the other or nothing can be a subnet of it.
                            elif (fw_net in sel_net or fw_net.subnet_of(sel_net)):

                                # NOTE: i think any subnet or host contained in shadower should be marked as duplicate
                                # this will allow for logic in modifying rules if app/service arent consistent
                                duplicate_networks[t_ip].append(fw_net)
                        except (TypeError, AttributeError) as E:
                            pass

            if not all(['src_net' in duplicate_networks, 'dst_net' in duplicate_networks]):
                # print(f'no {t_ip} address match')
                continue

            common_services = {
                'src_svc': {proto: port_to_range(svcs) for proto, svcs in common_src_services.items()},
                'dst_svc': {proto: port_to_range(svcs) for proto, svcs in common_dst_services.items()}
            }

            shadow_rule_results.append(
                SHADOW_RULE(fw_rule.pos, fw_rule.action, duplicate_networks, common_services)
            )

        return shadow_rule_results

    # def analyze_drop_rules(self):
    #     drop_rule_conflicts = []
    #     for shadower_name, shadowed_rules in self.shadow_rule_map.items():
    #         for rule in shadowed_rules:
    #             shadowed_name = self.loaded_fw_rules_index[rule.pos]
    #             full_shadowed_rule = self.loaded_fw_rules.get(shadowed_name)
    #
    #             # if we see a drop rule being shadowed by another rule, we will notify that the shadowed rule
    #             # must stay below the shadower or change of permissions may result.
    #             if full_shadowed_rule.action == 'deny':
    #                 # full_shadower_rule = self.loaded_fw_rules.get(shadower_name)
    #                 drop_rule_conflicts.append([shadower_name, shadowed_name])
    #
    #     for conflict in drop_rule_conflicts:
    #         print(f'Rule {conflict[0]} must stay above {conflict[1]}')
    #
    # def identify_drop_rules(self):
    #     for rule, pos in self.drop_rules.items():
    #         print(f'name={rule}, position={pos}')


# ==========================
# TESTING
# ==========================
# create a shadow rule chain and how they correlate to each other

# have a module where we can move any rule somewhere else and see if some result changes
#   - specific to block rules

# create an add rule method. this would be used to check if inserting a rule would cause something of note
#   examples:
#     will be shadowed by a higher rule
#     will shadow a lower rule
#     will override the decision of a lower rule (drop put above an explicit allow)

# if (__name__ == '__main__'):
#     # initiating jobs
#     analyzer = FirewallAnalyze()
#
#     analyzer.build_shadow_map()
#     analyzer.resolve_conflicts()
#     # analyzer.analyze_drop_rules()
#
#     flows = [
#         TRAFFIC_FLOW(*[11, IPv4Address('192.168.100.10'), (6, 69), 10, IPv4Address('192.168.200.24'), (6, 6969)]),
#         TRAFFIC_FLOW(*[11, IPv4Address('192.168.100.10'), (17, 69), 10, IPv4Address('192.168.200.24'), (17, 6969)]),
#         TRAFFIC_FLOW(*[11, IPv4Address('192.168.83.10'), (6, 69), 10, IPv4Address('192.168.200.24'), (6, 6969)]),
#         TRAFFIC_FLOW(*[11, IPv4Address('192.168.83.10'), (17, 69), 10, IPv4Address('192.168.200.24'), (17, 6969)]),
#     ]
#
#     for fl in flows:
#         res = analyzer.check_flow(fl)
#         print('FLOW CHECK RESULTS: ', res)

    # analyzer.identify_drop_rules()
