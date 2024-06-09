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

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import apkeep.core.ChangeItem;
import apkeep.rules.FieldType;
import apkeep.rules.FilterRule;
import apkeep.rules.Rule;
import apkeep.utils.Logger;
import common.ACLRule;
import common.BDDACLWrapper;
import common.BDDFieldWrapper;
import jdd.bdd.BDD;

public class ACLElement extends Element {

  private LinkedList<Rule> acl_rule;

  public ACLElement(String ename) {
    super(ename);
    acl_rule = new LinkedList<>();
  }

  @Override
  public void initialize() {
    // initialize the rule list with a default deny rule
    Map<FieldType, Integer> matchBDD = new HashMap<>();
    Map<FieldType, Integer> hitBDD = new HashMap<>();
    for (FieldType fieldType : FieldType.values()) {
      matchBDD.put(fieldType, BDDFieldWrapper.BDDTrue);
      hitBDD.put(fieldType, BDDFieldWrapper.BDDTrue);
    }
    FilterRule rule = new FilterRule(matchBDD, hitBDD, "deny", -1);
    acl_rule.add(rule);

    // initialize the AP set for port deny
    String deny_port = "deny";
    Map<FieldType, Set<Integer>> allFieldsTrue = new HashMap<>();
    for (FieldType fieldType : FieldType.values()) {
      Set<Integer> allTrue = new HashSet<>();
      allTrue.add(BDDFieldWrapper.BDDTrue);
      allFieldsTrue.put(fieldType, allTrue);
    }

    port_aps_raw.put(deny_port, allFieldsTrue);

    // initialize the AP set for port permit
    String permit_port = "permit";
    Map<FieldType, Set<Integer>> allFieldsFalse = new HashMap<>();
    for (FieldType fieldType : FieldType.values()) {
      Set<Integer> allFalse = new HashSet<>();
      allFieldsTrue.put(fieldType, allFalse);
    }
    port_aps_raw.put(permit_port, allFieldsFalse);
  }

  @Override
  public Rule encodeOneRule(String rule) {
    String[] tokens = rule.split(" ");
    ACLRule r =
        new ACLRule(
            rule.substring(tokens[0].length() + tokens[1].length() + tokens[2].length() + 3));

    Map<FieldType, Integer> match_bdd = apk.encodeACLBDD(r);
    return new FilterRule(match_bdd, r);
  }

  @Override
  public List<ChangeItem> insertOneRule(Rule rule) throws Exception {
    List<ChangeItem> change_set = identifyChangesInsert(rule, acl_rule);
    if (!port_aps_raw.containsKey(rule.getPort())) {
      Map<FieldType, Set<Integer>> newPortAps = new HashMap<>();
      for (FieldType fieldType : FieldType.values()) {
        newPortAps.put(fieldType, new HashSet<>());
      }
      port_aps_raw.put(rule.getPort(), newPortAps);
    }
    return change_set;
  }

  @Override
  public List<ChangeItem> removeOneRule(Rule rule) throws Exception {
    int index = findRule(rule);
    if (index == acl_rule.size()) {
      Logger.logInfo("Rule not found " + rule.toString());
      return new ArrayList<ChangeItem>();
    }
    Rule rule_to_remove = acl_rule.get(index);
    // remove if rule hits no packets
    if (!rule_to_remove.ruleHitsSomePackets()) {
      removeRule(index);
      Logger.logInfo("hidden rule deleted");
      return new ArrayList<ChangeItem>();
    }

    List<ChangeItem> change_set = identifyChangesRemove(rule_to_remove, acl_rule);
    removeRule(index);
    return change_set;
  }

  private int findRule(Rule rule) {
    int index = 0;
    for (Rule r : acl_rule) {
      if (r.equals(rule)) return index;
      index++;
    }
    return index;
  }

  private void removeRule(int index) {
    Rule rule = acl_rule.get(index);
    for (FieldType fieldType : FieldType.values()) {
      _fieldBdds.get(fieldType).deref(acl_rule.get(index).getMatchBdd().get(fieldType));
    }
    acl_rule.remove(index);
  }

  @Override
  protected int tryMergeIfNATElement(int delta) {
    return delta;
  }
}
