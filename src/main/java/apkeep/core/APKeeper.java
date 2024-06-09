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
package apkeep.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import apkeep.elements.ACLElement;
import apkeep.elements.Element;
import apkeep.exception.APNotFoundException;
import apkeep.exception.APSetNotFoundException;
import apkeep.exception.MergeSelfException;
import apkeep.rules.FieldType;
import apkeep.utils.Logger;
import apkeep.utils.Parameters;
import common.ACLRule;
import common.BDDACLWrapper;
import common.BDDFieldWrapper;
import common.BDDIpWrapper;
import common.PositionTuple;
import common.Utility;
import jdd.bdd.BDD;

/** Computes Atomic Predicates using BDDs. */
public class APKeeper {
  private static final boolean MergeAP = Parameters.MergeAP;

  //	public static BDDACLWrapper bddengine;
  public static Map<FieldType, BDDFieldWrapper> _fieldBDDEngines;
  //	private Set<Integer> AP;
  private HashMap<FieldType, Set<Integer>> _aps;

  private Map<String, Element> elements;
  int element_number = 0;
  HashMap<String, Integer> element_ids;
  HashMap<Integer, String> id_element;
  HashSet<String> nat_names;

  //	HashMap<Integer, ArrayList<String>> ap_ports;
  HashMap<FieldType, HashMap<Integer, ArrayList<String>>> _ap2Ports;
  HashMap<ArrayList<String>, HashMap<FieldType, HashSet<Integer>>> _ports2Aps;
  HashSet<ArrayList<String>> ports_to_merge;

  private Map<FieldType, Integer> mergeable_aps = new HashMap<>();
  HashMap<String, Integer> cachePrefixBDD;

  //	public APKeeper(BDDACLWrapper bdd_engine) {
  public APKeeper(Map<FieldType, BDDFieldWrapper> fieldBDDEngines) {
    _fieldBDDEngines = fieldBDDEngines;
    _aps = new HashMap<>();

    element_ids = new HashMap<String, Integer>();
    id_element = new HashMap<>();
    elements = new HashMap<String, Element>();
    nat_names = new HashSet<String>();

    //		ap_ports = new HashMap<Integer, ArrayList<String>>();
    _ap2Ports = new HashMap<>();
    for (FieldType fieldType : FieldType.values()) {
      _aps.put(fieldType, new HashSet<>());
      _ap2Ports.put(fieldType, new HashMap<>());
    }
    _ports2Aps = new HashMap<>();
    ports_to_merge = new HashSet<ArrayList<String>>();

    cachePrefixBDD = new HashMap<>();
  }

  public void addElement(String ename, Element e) {
    elements.put(ename, e);
    element_ids.put(ename, element_number);
    id_element.put(element_number, ename);
    element_number++;
  }

  public void initialize() {
    int element_number = elements.keySet().size();
    ArrayList<String> ports = new ArrayList<String>(element_number);
    HashMap<FieldType, HashSet<Integer>> aps = new HashMap<>();

    for (int i = 0; i < element_number; i++) {
      ports.add("default");
    }
    for (String ename : elements.keySet()) {
      Element e = elements.get(ename);
      int element_id = element_ids.get(ename);
      if (e instanceof ACLElement) {
        ports.set(element_id, "deny");
      }
      //			else if (e instanceof NATElement) {
      //				nat_names.add(ename);
      //			}
    }

    for (FieldType fieldType : FieldType.values()) {
      _ap2Ports.get(fieldType).put(BDDFieldWrapper.BDDTrue, ports);
      aps.put(fieldType, new HashSet<>());
      aps.get(fieldType).add(BDDFieldWrapper.BDDTrue);
      _aps.put(fieldType, new HashSet<>());
      _aps.get(fieldType).add(BDDFieldWrapper.BDDTrue);
    }
    //		_ap2Ports.put(BDDFieldWrapper.BDDTrue, ports);

    //		ports_aps.put(ports, aps);
    _ports2Aps.put(ports, aps);
  }

  public boolean hasAP(FieldType field, int ap) {
    return _aps.get(field).contains(ap);
  }

  public int getAPNum(FieldType field) {
    return _aps.get(field).size();
  }

  public Set<PositionTuple> getHoldPorts(FieldType field, int ap) throws Exception {
    if (!hasAP(field, ap)) {
      throw new APNotFoundException(ap);
    }

    Set<PositionTuple> pts = new HashSet<>();
    for (int index = 0; index < _ap2Ports.get(field).get(ap).size(); index++) {
      if (_ap2Ports.get(field).get(ap).get(index).equals("default")) continue;
      pts.add(new PositionTuple(id_element.get(index), _ap2Ports.get(field).get(ap).get(index)));
    }

    return pts;
  }

  /**
   * @param PredicateBDD
   * @return if the acl is true or force, return the set containing the acl itself; otherwise,
   *     return an ap expression
   */
  public HashSet<Integer> getAPExp(FieldType field, int PredicateBDD) {
    HashSet<Integer> apexp = new HashSet<Integer>();
    // get the expression
    if (PredicateBDD == BDDFieldWrapper.BDDFalse) {
      return apexp;
    } else if (PredicateBDD == BDDFieldWrapper.BDDTrue) {
      return new HashSet<>(_aps.get(field));
      //			return new HashSet<Integer>(_aps);
    }

    for (int oneap : _aps.get(field)) {
      if (_fieldBDDEngines.get(field).getBDD().and(oneap, PredicateBDD) != BDDACLWrapper.BDDFalse) {
        apexp.add(oneap);
      }
    }
    return apexp;
  }

  /**
   * add one predicate and recompute APs
   *
   * @throws Exception
   */
  public void addPredicate(FieldType field, int pred) throws Exception {

    BDD thebdd = _fieldBDDEngines.get(field).getBDD();

    int predneg = thebdd.not(pred);
    thebdd.ref(predneg);

    HashSet<Integer> oldList = new HashSet<Integer>(_aps.get(field));

    for (int oldap : oldList) {
      int parta = thebdd.and(pred, oldap);
      if (parta != BDDACLWrapper.BDDFalse) {
        int partb = thebdd.and(predneg, oldap);
        if (partb != BDDACLWrapper.BDDFalse) {
          updateSplitAP(field, oldap, parta, partb);
        }
      }
    }
  }

  public int encodePrefixBDD(long destip, int prefixlen) {
    String prefix = destip + " " + prefixlen;
    if (cachePrefixBDD.containsKey(prefix)) {
      return cachePrefixBDD.get(prefix);
    } else {
      int prefixbdd =
          ((BDDIpWrapper) _fieldBDDEngines.get(FieldType.dstIp)).encodeIPPrefix(destip, prefixlen);
      cachePrefixBDD.put(prefix, prefixbdd);
      return prefixbdd;
    }
  }

  public void removePrefixBDD(long destip, int prefixlen) {
    String prefix = destip + " " + prefixlen;
    if (cachePrefixBDD.containsKey(prefix)) {
      cachePrefixBDD.remove(prefix);
    }
  }

  public Map<FieldType, Integer> encodeACLBDD(ACLRule rule) {
    HashMap<FieldType, Integer> aclBDDs = new HashMap<>();
    for (Entry<FieldType, BDDFieldWrapper> entry : _fieldBDDEngines.entrySet()) {
      BDDFieldWrapper BDDEngine = entry.getValue();
      aclBDDs.put(entry.getKey(), BDDEngine.convertAclRule(rule));
      entry.getValue().convertAclRule(rule);
    }
    return aclBDDs;
  }

  @SuppressWarnings("unchecked")
  public void updateSplitAP(FieldType fieldType, int origin, int parta, int partb)
      throws Exception {
    Logger.logDebugInfo("Splitting " + origin + " -> " + parta + " + " + partb);
    if (!hasAP(fieldType, origin)) {
      throw new APNotFoundException(origin);
    }

    _aps.get(fieldType).remove(origin);
    _aps.get(fieldType).add(parta);
    _aps.get(fieldType).add(partb);

    if (_ap2Ports.get(fieldType).containsKey(origin)) {
      ArrayList<String> ports = _ap2Ports.get(fieldType).get(origin);
      _ap2Ports.get(fieldType).put(parta, ports);
      _ap2Ports.get(fieldType).put(partb, (ArrayList<String>) ports.clone());

      // update each element's AP set
      for (String elementname : elements.keySet()) {
        String port = ports.get(element_ids.get(elementname));
        elements.get(elementname).updateAPSplit(fieldType, port, origin, parta, partb);
      }

      _ap2Ports.get(fieldType).remove(origin);

      if (MergeAP) {
        _ports2Aps.get(ports).get(fieldType).remove(origin);
        _ports2Aps.get(ports).get(fieldType).add(parta);
        _ports2Aps.get(ports).get(fieldType).add(partb);
        mergeable_aps.merge(fieldType, 1, Integer::sum);
      }
    }

    _fieldBDDEngines.get(fieldType).ref(parta);
    _fieldBDDEngines.get(fieldType).ref(partb);
    _fieldBDDEngines.get(fieldType).deref(origin);

    /*
     * enabling Consistent check will affect efficiency
     */
    //		if(!ap_ports.keySet().equals(AP)) {
    //			throw new APInconsistentException("merge");
    //		}
  }

  public void updateTransferAP(FieldType fieldType, PositionTuple pt1, PositionTuple pt2, int ap)
      throws APNotFoundException {
    if (!_ap2Ports.get(fieldType).containsKey(ap)) {
      throw new APNotFoundException(ap);
    }

    ArrayList<String> ports = _ap2Ports.get(fieldType).get(ap);

    if (!MergeAP) {
      ports.set(element_ids.get(pt2.getDeviceName()), pt2.getPortName());
    } else {
      HashSet<Integer> aps = _ports2Aps.get(ports).get(fieldType);
      aps.remove(ap);

      if (aps.isEmpty()) {
        _ports2Aps.get(ports).remove(fieldType);
        if (_ports2Aps.get(ports).isEmpty()) {
          _ports2Aps.remove(ports);
        }
      }
      // the ap set is non-empty, then clone the ports
      else {
        mergeable_aps.merge(fieldType, -1, Integer::sum);

        // the ap set has one ap, then do not merge it
        if (aps.size() == 1) {
          ports_to_merge.remove(ports);
        }

        ports = new ArrayList<>(ports);
      }

      ports.set(element_ids.get(pt2.getDeviceName()), pt2.getPortName());
      _ap2Ports.get(fieldType).put(ap, ports);

      if (!_ports2Aps.containsKey(ports)) {
        _ports2Aps.put(ports, new HashMap<>());
        _ports2Aps.get(ports).put(fieldType, new HashSet<>());
      }
      aps = _ports2Aps.get(ports).get(fieldType);
      if (!aps.isEmpty()) {
        mergeable_aps.merge(fieldType, 1, Integer::sum);
      }
      aps.add(ap);
      if (aps.size() == 2) {
        ports_to_merge.add(ports);
      }
    }
  }

  public boolean checkRWMergable(int ap1, int ap2) {
    if (nat_names.isEmpty()) return true;
    //		for (String nat_name : nat_names) {
    //			NATElement nat = (NATElement) elements.get(nat_name);
    //			if (!nat.isMergable(ap1, ap2)) return false;
    //		}
    return true;
  }

  public boolean checkRWMergable(HashSet<Integer> aps) {
    if (nat_names.isEmpty()) return true;
    //		for (String nat_name : nat_names) {
    //			NATElement nat = (NATElement) elements.get(nat_name);
    //			if (!nat.isMergable(aps)) return false;
    //		}
    return true;
  }

  public boolean isMergeable(FieldType fieldType) {
    if (mergeable_aps.get(fieldType) == null) {
      return false;
    }
    if (_aps.get(fieldType).size() > Parameters.TOTAL_AP_THRESHOLD
        && mergeable_aps.get(fieldType) > Parameters.LOW_MERGEABLE_AP_THRESHOLD) return true;
    if (mergeable_aps.get(fieldType) > Parameters.HIGH_MERGEABLE_AP_THRESHOLD) return true;
    return false;
  }

  public int tryMergeAP(FieldType fieldType, int ap) throws Exception {
    if (!MergeAP) return ap;

    ArrayList<String> ports = _ap2Ports.get(fieldType).get(ap);
    HashSet<Integer> aps = _ports2Aps.get(ports).get(fieldType);
    if (aps.size() > 1) {
      for (int one_ap : aps) {
        if (one_ap == ap) continue;
        if (!checkRWMergable(one_ap, ap)) continue;
        int merged_ap = _fieldBDDEngines.get(fieldType).or(ap, one_ap);
        mergeable_aps.merge(fieldType, -1, Integer::sum);
        updateMergeAP(fieldType, one_ap, ap, merged_ap);
        if (aps.size() == 1) {
          ports_to_merge.remove(ports);
        }
        return merged_ap;
      }
    }
    return ap;
  }

  public void tryMergeAPBatch(FieldType field) throws Exception {
    if (ports_to_merge.isEmpty()) return;

    for (ArrayList<String> ports : new ArrayList<>(ports_to_merge)) {
      HashSet<Integer> aps = _ports2Aps.get(ports).get(field);
      if (aps.size() < 2) {
        throw new MergeSelfException(aps.toArray()[0]);
      }
      if (!checkRWMergable(aps)) continue;

      int[] apsarr = aps.stream().mapToInt(Number::intValue).toArray();
      int merged_ap = _fieldBDDEngines.get(field).OrInBatch(apsarr);
      mergeable_aps.merge(field, 1 - aps.size(), Integer::sum);
      updateMergeAPBatch(field, merged_ap, aps);
      ports_to_merge.remove(ports);
    }
  }

  public void updateMergeAP(FieldType fieldType, int ap1, int ap2, int merged_ap) throws Exception {
    Logger.logDebugInfo("Merging " + ap1 + " + " + ap2 + " -> " + merged_ap);
    if (!_aps.get(fieldType).contains(ap1)) {
      throw new APNotFoundException(ap1);
    }
    if (!_aps.get(fieldType).contains(ap2)) {
      throw new APNotFoundException(ap2);
    }
    _aps.get(fieldType).remove(ap1);
    _aps.get(fieldType).remove(ap2);
    _aps.get(fieldType).add(merged_ap);

    ArrayList<String> ports = _ap2Ports.get(fieldType).get(ap1);
    for (String elementname : elements.keySet()) {
      String port = ports.get(element_ids.get(elementname));
      elements.get(elementname).updateAPSetMerge(fieldType, port, merged_ap, ap1, ap2);
    }
    _ap2Ports.get(fieldType).remove(ap1);
    _ap2Ports.get(fieldType).remove(ap2);
    _ap2Ports.get(fieldType).put(merged_ap, ports);

    HashSet<Integer> aps = _ports2Aps.get(ports).get(fieldType);
    aps.remove(ap1);
    aps.remove(ap2);
    aps.add(merged_ap);

    _fieldBDDEngines.get(fieldType).deref(ap1);
    _fieldBDDEngines.get(fieldType).deref(ap2);

    /*
     * enabling Consistent check will affect efficiency
     */
    //		if(!ap_ports.keySet().equals(AP)) {
    //			throw new APInconsistentException("merge");
    //		}
  }

  public void updateMergeAPBatch(FieldType fieldType, int merged_ap, HashSet<Integer> aps)
      throws Exception {
    Logger.logDebugInfo("Merging " + aps + " -> " + merged_ap);
    if (!_aps.get(fieldType).containsAll(aps)) {
      throw new APSetNotFoundException(aps);
    }

    _aps.get(fieldType).removeAll(aps);
    _aps.get(fieldType).add(merged_ap);

    ArrayList<String> ports = _ap2Ports.get(fieldType).get(aps.toArray()[0]);
    _ap2Ports.get(fieldType).put(merged_ap, ports);
    for (String elementname : elements.keySet()) {
      String port = ports.get(element_ids.get(elementname));
      elements.get(elementname).updateAPSetMergeBatch(fieldType, port, merged_ap, aps);
    }
    for (int ap : aps) {
      _fieldBDDEngines.get(fieldType).deref(ap);
      _ap2Ports.get(fieldType).remove(ap);
    }

    aps.clear();
    aps.add(merged_ap);

    /*
     * enabling Consistent check will affect efficiency
     */
    //		if(!ap_ports.keySet().equals(AP)) {
    //			throw new APInconsistentException("merge");
    //		}
  }

  public static HashSet<String> getAPPrefixes(FieldType field, Set<Integer> aps) {
    HashSet<String> ip_prefixs = new HashSet<String>();
    int total_bits =
        BDDACLWrapper.protocolBits
            + 2 * BDDACLWrapper.portBits
            + 3 * BDDACLWrapper.ipBits
            + BDDACLWrapper.mplsBits
            + BDDACLWrapper.ip6Bits;
    int[] header = new int[total_bits];
    int[] dstip = new int[32];

    for (int ap_origin : aps) {
      int ap = ap_origin;
      while (ap != BDDACLWrapper.BDDFalse) {
        _fieldBDDEngines.get(field).getBDD().oneSat(ap, header);
        int offset = 32 + 1;
        int prefix_len = 32;
        for (int i = 0; i < 32; i++) {
          if (header[offset + i] == -1) {
            dstip[i] = 0;
            prefix_len--;
          } else {
            dstip[i] = header[offset + i];
          }
        }
        String ip_prefix = Utility.IpBinToString(dstip);
        long ip_prefix_long = Utility.IPStringToLong(ip_prefix);
        ip_prefixs.add(ip_prefix + "/" + prefix_len);
        int prefix_bdd =
            ((BDDIpWrapper) _fieldBDDEngines.get("dstIp"))
                .encodeIPPrefix(ip_prefix_long, prefix_len);
        ap = _fieldBDDEngines.get(field).diff(ap, prefix_bdd);
      }
    }
    return ip_prefixs;
  }
}
