package apkeep.checker;

import apkeep.core.FieldSeperatedNetwork;
import apkeep.elements.ACLElement;
import apkeep.elements.Element;
import apkeep.elements.ForwardElement;
import apkeep.rules.FieldType;
import common.BDDFieldWrapper;
import common.PositionTuple;

import java.util.*;

public class FieldSeperatedChecker {

  FieldSeperatedNetwork net;
  Set<Loop> loops;

  public FieldSeperatedChecker(FieldSeperatedNetwork net) {
    this.net = net;
    loops = new HashSet<>();
  }

  public Set<Loop> getLoops() {
    return loops;
  }

  public ForwardingGraph constructFowardingGraph(PositionTuple pt1) {
    Map<PositionTuple, Map<FieldType, Set<Integer>>> port_aps = new HashMap<>();
    Map<String, Set<PositionTuple>> node_ports = new HashMap<>();

    Element e = getElement(pt1.getDeviceName());

    Map<FieldType, Set<Integer>> aps = e.getPortAPs(pt1.getPortName());

    if (aps == null) return null;
    for (FieldType fieldType : FieldType.values()) {
      if (aps.get(fieldType) == null) return null;
    }

    for (FieldType fieldType : FieldType.values()) {
      Set<Integer> fieldAps = aps.get(fieldType);
      for (int ap : fieldAps) {
        Set<PositionTuple> pts = null;
        try {
          pts = net.getHoldPorts(fieldType, ap);
        } catch (Exception e1) {
          e1.printStackTrace();
        }
        for (PositionTuple pt : pts) {
          port_aps.putIfAbsent(pt, new HashMap<>());
          if (!port_aps.get(pt).containsKey(fieldType)) {
            port_aps.get(pt).put(fieldType, new HashSet<>());
          }
          port_aps.get(pt).get(fieldType).add(ap);

          node_ports.putIfAbsent(pt.getDeviceName(), new HashSet<>());
          node_ports.get(pt.getDeviceName()).add(pt);
        }
      }
    }

    return new ForwardingGraph(port_aps, node_ports);
  }

  public int checkProperty(ForwardingGraph g) {
    loops.clear();

    for (PositionTuple pt : g.port_aps.keySet()) {
      Map<FieldType, Set<Integer>> aps = new HashMap<>(g.port_aps.get(pt));
      ArrayList<PositionTuple> history = new ArrayList<PositionTuple>();
      traverseFowardingGraph(pt, aps, history, g);
    }

    return loops.size();
  }

  private void traverseFowardingGraph(
      PositionTuple cur_hop,
      Map<FieldType, Set<Integer>> fwd_aps,
      ArrayList<PositionTuple> history,
      ForwardingGraph g) {
    if (fwd_aps.isEmpty()) return;
    /*
     * check loops
     */
    if (checkLoop(history, cur_hop, fwd_aps, null)) return;
    history.add(cur_hop);

    /*
     * look up l1-topology for connected node
     */
    if (net.getConnectedPorts(cur_hop) == null) return;
    for (PositionTuple connected_pt : net.getConnectedPorts(cur_hop)) {
      String next_node = connected_pt.getDeviceName();
      if (!g.node_ports.containsKey(next_node)) continue;
      for (PositionTuple next_hop : g.node_ports.get(next_node)) {
        if (next_hop.equals(connected_pt)) continue;
        Map<FieldType, Set<Integer>> aps = new HashMap<>(g.port_aps.get(next_hop));
        for (FieldType fieldType : FieldType.values()) {
          aps.get(fieldType).retainAll(fwd_aps.get(fieldType));
        }
        ArrayList<PositionTuple> new_history = new ArrayList<>(history);
        new_history.add(connected_pt);
        traverseFowardingGraph(next_hop, aps, new_history, g);
      }
    }
  }

  public void checkProperty(String element_name, Map<FieldType, Set<Integer>> moved_aps) {
    loops.clear();

    Element e = net.getElement(element_name);
    for (String port : e.getPorts()) {
      if (port.equals("default") || e.getPortAPs(port).isEmpty()) continue;

      Map<FieldType, Set<Integer>> aps = new HashMap<>(moved_aps);

      for (FieldType fieldType : FieldType.values()) {
        aps.get(fieldType).retainAll(e.getPortAPs(port).get(fieldType));
      }

      boolean isApEmpty = true;
      for (FieldType fieldType : FieldType.values()) {
        isApEmpty &= aps.get(fieldType).isEmpty();
      }
      if (isApEmpty) continue;
      Set<String> ports = getPhysicalPorts(e, port);
      for (String next_port : ports) {
        PositionTuple next_hop = new PositionTuple(element_name, next_port);
        ArrayList<PositionTuple> history = new ArrayList<>();
        traversePPM(next_hop, aps, history);
      }
    }
  }

  public void checkPropertyDivision(String element_name, Map<FieldType, Set<Integer>> moved_aps) {
    loops.clear();

    boolean isACL = false;
    if (net.getElement(element_name) instanceof ACLElement) {
      if (net.getConnectedPorts(new PositionTuple(element_name, "permit")) == null) return;
      isACL = true;
    }

    element_name = net.getForwardElement(element_name);
    Element e = net.getElement(element_name);

    for (String port : e.getPorts()) {
      if (port.equals("default") || e.getPortAPs(port).isEmpty()) continue;

      Map<FieldType, Set<Integer>> fwd_aps = new HashMap<>();
      Map<FieldType, Set<Integer>> acl_aps = new HashMap<>();
      if (isACL) {
        fwd_aps.putAll(e.getPortAPs(port));
        acl_aps.putAll(moved_aps);
      } else {
        fwd_aps.putAll(moved_aps);
        for (FieldType fieldType : FieldType.values()) {
          fwd_aps.get(fieldType).retainAll(e.getPortAPs(port).get(fieldType));
          acl_aps.get(fieldType).add(BDDFieldWrapper.BDDTrue);
        }
      }

      boolean isFwdEmpty = true;
      boolean isAclEmpty = true;
      for (FieldType fieldType : FieldType.values()) {
        isFwdEmpty &= (fwd_aps.get(fieldType).isEmpty());
        isAclEmpty &= (acl_aps.get(fieldType).isEmpty());
      }
      if (isFwdEmpty || isAclEmpty) continue;

      Set<String> ports = getPhysicalPorts(e, port);
      for (String next_port : ports) {
        PositionTuple next_hop = new PositionTuple(element_name, next_port);
        ArrayList<PositionTuple> history = new ArrayList<>();
        traversePPMDivision(next_hop, fwd_aps, acl_aps, history);
      }
    }
  }

  private void traversePPM(
      PositionTuple cur_hop, Map<FieldType, Set<Integer>> fwd_aps, List<PositionTuple> history) {

    if (fwd_aps.isEmpty()) return;
    /*
     * check loops
     */
    if (checkLoop(history, cur_hop, fwd_aps, null)) return;
    history.add(cur_hop);

    /*
     * look up l1-topology for connected node
     */
    if (net.getConnectedPorts(cur_hop) == null) return;
    for (PositionTuple connected_pt : net.getConnectedPorts(cur_hop)) {
      String next_node = connected_pt.getDeviceName();
      Element e = getElement(next_node);
      for (String port : e.getPorts()) {
        if (port.equals(connected_pt.getPortName())) continue;
        Map<FieldType, Set<Integer>> aps = e.forwardAPs(port, fwd_aps);
        Set<String> ports = getPhysicalPorts(e, port);
        for (String next_port : ports) {
          if (next_port.equals(connected_pt.getPortName())) continue;
          PositionTuple next_hop = new PositionTuple(next_node, next_port);
          ArrayList<PositionTuple> new_history = new ArrayList<>(history);
          new_history.add(connected_pt);
          traversePPM(next_hop, aps, new_history);
        }
      }
    }
  }

  private void traversePPMDivision(
      PositionTuple cur_hop,
      Map<FieldType, Set<Integer>> fwd_aps,
      Map<FieldType, Set<Integer>> acl_aps,
      List<PositionTuple> history) {
    if (fwd_aps.isEmpty() || acl_aps.isEmpty()) return;
    if (cur_hop.getPortName().equals("deny")) return;

    /*
     * check loops
     */
    if (checkLoop(history, cur_hop, fwd_aps, acl_aps)) return;
    history.add(cur_hop);

    /*
     * look up l1-topology for connected node
     */
    if (net.getConnectedPorts(cur_hop) == null) return;
    for (PositionTuple connected_pt : net.getConnectedPorts(cur_hop)) {
      String next_node = connected_pt.getDeviceName();
      Element e = getElement(next_node);
      Map<FieldType, Set<Integer>> filtered_fwd_aps = new HashMap<>(fwd_aps);
      Map<FieldType, Set<Integer>> filtered_acl_aps = new HashMap<>(acl_aps);
      for (String port : e.getPorts()) {
        if (port.equals(connected_pt.getPortName())) continue;
        if (e instanceof ACLElement) {
          filtered_acl_aps = e.forwardAPs(port, acl_aps);
        } else {
          filtered_fwd_aps = e.forwardAPs(port, fwd_aps);
        }
        Set<String> ports = getPhysicalPorts(e, port);
        for (String next_port : ports) {
          if (next_port.equals(connected_pt.getPortName())) continue;
          PositionTuple next_hop = new PositionTuple(next_node, next_port);
          ArrayList<PositionTuple> new_history = new ArrayList<>(history);
          new_history.add(connected_pt);
          traversePPMDivision(next_hop, filtered_fwd_aps, filtered_acl_aps, new_history);
        }
      }
    }
  }

  private boolean checkLoop(
      List<PositionTuple> history,
      PositionTuple cur_hop,
      Map<FieldType, Set<Integer>> fwd_aps,
      Map<FieldType, Set<Integer>> acl_aps) {
    if (history.contains(cur_hop)) {
      if (acl_aps != null) {
        boolean hasOverLap = false;
        for (FieldType fieldType : FieldType.values()) {
          hasOverLap |=
              Element.hasOverlap(fieldType, fwd_aps.get(fieldType), acl_aps.get(fieldType));
        }
        return !hasOverLap;
      }
      history.add(cur_hop);
      Loop loop = new Loop(fwd_aps.get(FieldType.dstIp), history, cur_hop);
      loops.add(loop);
      return true;
    }
    return false;
  }

  private Element getElement(String node_name) {
    if (net.isACLNode(node_name)) return net.getACLElement(node_name);
    return net.getElement(node_name);
  }

  private Set<String> getPhysicalPorts(Element e, String port) {
    if (e instanceof ForwardElement) {
      if (port.toLowerCase().startsWith("vlan")) {
        return ((ForwardElement) e).getVlanPorts(port);
      }
    }
    Set<String> ports = new HashSet<>();
    ports.add(port);
    return ports;
  }
}
