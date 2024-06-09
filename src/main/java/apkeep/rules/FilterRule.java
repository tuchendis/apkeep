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
package apkeep.rules;

import common.ACLRule;

import java.util.Map;

public class FilterRule extends Rule {
  public String _accessList;
  public String _accessListNumber;
  public String _protocolLower;
  public String _protocolUpper;
  public String _source;
  public String _sourceWildcard;
  public String _sourcePortLower;
  public String _sourcePortUpper;
  public String _destination;
  public String _destinationWildcard;
  public String _destinationPortLower;
  public String _destinationPortUpper;

  public FilterRule(
      Map<FieldType, Integer> matchBdd,
      Map<FieldType, Integer> hit_bdd,
      String port,
      int priority) {
    super(matchBdd, hit_bdd, priority, port);
    this._accessList = null;
    this._accessListNumber = null;
    this._protocolLower = null;
    this._protocolUpper = null;
    this._source = null;
    this._sourceWildcard = null;
    this._sourcePortLower = null;
    this._sourcePortUpper = null;
    this._destination = null;
    this._destinationWildcard = null;
    this._destinationPortLower = null;
    this._destinationPortUpper = null;
  }

  public FilterRule(Map<FieldType, Integer> matchBdd, ACLRule rule) {
    super(matchBdd, rule.priority, rule.permitDeny);
    this._accessList = rule.accessList;
    this._accessListNumber = rule.accessListNumber;
    this._protocolLower = rule.protocolLower;
    this._protocolUpper = rule.protocolUpper;
    this._source = rule.source;
    this._sourceWildcard = rule.sourceWildcard;
    this._sourcePortLower = rule.sourcePortLower;
    this._sourcePortUpper = rule.sourcePortUpper;
    this._destination = rule.destination;
    this._destinationWildcard = rule.destinationWildcard;
    this._destinationPortLower = rule.destinationPortLower;
    this._destinationPortUpper = rule.destinationPortUpper;
  }

  @Override
  public boolean equals(Object o) {
    if (o instanceof FilterRule) {
      FilterRule another = (FilterRule) o;
      if (this.toString().equals(another.toString())) return true;
    }
    return false;
  }

  public String toString() {
    return _accessList
        + " "
        + _accessListNumber
        + " "
        + _port
        + " "
        + _protocolLower
        + " "
        + _protocolUpper
        + " "
        + _source
        + " "
        + _sourceWildcard
        + " "
        + _sourcePortLower
        + " "
        + _sourcePortUpper
        + " "
        + _destination
        + " "
        + _destinationWildcard
        + " "
        + _destinationPortLower
        + " "
        + _destinationPortUpper
        + " "
        + _priority;
  }
}
