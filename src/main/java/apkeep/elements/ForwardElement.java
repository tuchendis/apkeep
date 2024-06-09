/**
 * APKeep
 *
 * <p>Copyright (c) 2020 ANTS Lab, Xi'an Jiaotong University. All rights reserved. Developed by:
 * PENG ZHANG and XU LIU.
 *
 * <p>Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal with the Software without
 * restriction, including without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * <p>1. Redistributions of source code must retain the above copyright notice, this list of
 * conditions and the following disclaimers.
 *
 * <p>2. Redistributions in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimers in the documentation and/or other materials provided
 * with the distribution.
 *
 * <p>3. Neither the name of the Xi'an Jiaotong University nor the names of the developers may be
 * used to endorse or promote products derived from this Software without specific prior written
 * permission.
 *
 * <p>4. Any report or paper describing results derived from using any part of this Software must
 * cite the following publication of the developers: Peng Zhang, Xu Liu, Hongkun Yang, Ning Kang,
 * Zhengchang Gu, and Hao Li, APKeep: Realtime Verification for Real Networks, In 17th USENIX
 * Symposium on Networked Systems Design and Implementation (NSDI 20), pp. 241-255. 2020.
 *
 * <p>THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 * BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS WITH THE SOFTWARE.
 */
package apkeep.elements;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import apkeep.core.ChangeItem;
import apkeep.rules.FieldType;
import apkeep.rules.ForwardingRule;
import apkeep.rules.Rule;
import apkeep.utils.Logger;
import apkeep.utils.TrieTree;
import apkeep.utils.TrieTreeNode;
import common.BDDACLWrapper;
import common.BDDFieldWrapper;

public class ForwardElement extends Element {

  TrieTree trie;
  Map<String, Set<String>> vlan_ports;

  public ForwardElement(String ename) {
    super(ename);
    trie = new TrieTree();
    vlan_ports = new HashMap<>();
  }

  @Override
  public void initialize() {
    String default_port = "default";
    Map<FieldType, Set<Integer>> allFieldsTrue = new HashMap<>();
    for (FieldType fieldType : FieldType.values()) {
      Set<Integer> allTrue = new HashSet<>();
      allTrue.add(BDDFieldWrapper.BDDTrue);
      allFieldsTrue.put(fieldType, allTrue);
    }
    port_aps_raw.put(default_port, allFieldsTrue);
  }

  public void addVlanPorts(Map<String, Set<String>> map) {
    vlan_ports.putAll(map);
  }

  public Set<String> getVlanPorts(String vlan) {
    if (vlan_ports.containsKey(vlan)) return vlan_ports.get(vlan);
    return new HashSet<>();
  }

  @Override
  public Rule encodeOneRule(String rule) {
    String[] tokens = rule.split(" ");
    long prefix = Long.valueOf(tokens[3]);
    int prefixlen = Integer.valueOf(tokens[4]);
    String port = tokens[5];
    int priority = Integer.valueOf(tokens[6]);

    Map<FieldType, Integer> matchBdd = new HashMap<>();
    int match_bdd = apk.encodePrefixBDD(prefix, prefixlen);
    matchBdd.put(FieldType.dstIp, match_bdd);

    return new ForwardingRule(matchBdd, prefix, prefixlen, port, priority);
  }

  @Override
  public List<ChangeItem> insertOneRule(Rule rule) throws Exception {
    // find the node in the trie
    TrieTreeNode node = trie.insert((ForwardingRule) rule);

    // duplicate rules
    if (node.hasRule(rule)) {
      Logger.logInfo("duplicate rule " + rule.toString());
      return new ArrayList<ChangeItem>();
    }

    // get the affected rules
    ArrayList<Rule> affected_rules = getAffectedRules(node);
    List<ChangeItem> change_set = identifyChangesInsert(rule, affected_rules);

    // check whether the forwarding port exists, if not create it,
    // and initialize the AP set of the port to empty
    if (!port_aps_raw.containsKey(rule.getPort())) {
      Map<FieldType, Set<Integer>> newPortAps = new HashMap<>();
      for (FieldType fieldType : FieldType.values()) {
        newPortAps.put(fieldType, new HashSet<>());
      }
      port_aps_raw.put(rule.getPort(), newPortAps);
    }

    // insert the rule
    node.addRule(rule);
    return change_set;
  }

  @Override
  public List<ChangeItem> removeOneRule(Rule rule) throws Exception {
    // find the node in the trie
    TrieTreeNode node = trie.search((ForwardingRule) rule);
    if (node == null) {
      Logger.logInfo("Node not found " + rule.toString());
      return new ArrayList<ChangeItem>();
    }

    // find the rule in the node
    Rule rule_to_remove = node.findRule(rule);
    if (rule_to_remove == null) {
      Logger.logInfo("Rule not found " + rule.toString());
      return new ArrayList<ChangeItem>();
    }

    // remove if rule hits no packets
    if (rule_to_remove.getFieldHitBdd(FieldType.dstIp) == BDDACLWrapper.BDDFalse) {
      removeRule(node, rule_to_remove);
      Logger.logInfo("hidden rule deleted");
      return new ArrayList<ChangeItem>();
    }

    // get the affected rules
    ArrayList<Rule> affected_rules = getAffectedRules(node);
    List<ChangeItem> change_set = identifyChangesRemove(rule_to_remove, affected_rules);

    removeRule(node, rule_to_remove);
    return change_set;
  }

  private ArrayList<Rule> getAffectedRules(TrieTreeNode node) {
    ArrayList<Rule> affected_rules = new ArrayList<>();
    affected_rules.addAll(node.getDescendantRules());
    affected_rules.addAll(node.getAncestorRules());
    affected_rules.addAll(node.getRules());
    Arrays.sort(affected_rules.toArray());
    return affected_rules;
  }

  private void removeRule(TrieTreeNode node, Rule rule) {
    node.removeRule(rule);
    if (node.noRules()) {
      ForwardingRule r = (ForwardingRule) rule;
      apk.removePrefixBDD(r.getDstIP(), r.getMaskLen());
      _fieldBdds.get(FieldType.dstIp).deref(rule.getMatchBdd().get(FieldType.dstIp));
      node.delete();
    }
  }

  @Override
  protected int tryMergeIfNATElement(int delta) {
    return delta;
  }
}
