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

import common.BDDFieldWrapper;

import java.util.HashMap;
import java.util.Map;

public abstract class Rule implements Comparable<Rule> {

  protected Map<FieldType, Integer> _matchBdd;
  protected Map<FieldType, Integer> _hitBdd;

  protected int _priority;
  protected String _port;

  public Rule(Map<FieldType, Integer> matchBdd, int priority, String port) {
    this._priority = priority;
    this._port = port;
    this._matchBdd = matchBdd;
    this._hitBdd = new HashMap<>();
    for (FieldType field : FieldType.values()) {
      this._hitBdd.put(field, BDDFieldWrapper.BDDFalse);
    }
  }

  protected Rule(
      Map<FieldType, Integer> matchBdd,
      Map<FieldType, Integer> hitBdd,
      int priority,
      String port) {
    this._priority = priority;
    this._port = port;
    this._matchBdd = matchBdd;
    this._hitBdd = hitBdd;
  }

  public boolean ruleHitsSomePackets() {
    boolean res = false;
    for (FieldType fieldType : FieldType.values()) {
      res |= _hitBdd.get(fieldType) != BDDFieldWrapper.BDDTrue;
    }
    return res;
  }

  public void setHitBdd(Map<FieldType, Integer> hitBdd) {
    this._hitBdd = hitBdd;
  }

  public void setFieldHitBdd(FieldType fieldType, Integer hitBdd) {
    this._hitBdd.put(fieldType, hitBdd);
  }

  public Map<FieldType, Integer> getMatchBdd() {
    return _matchBdd;
  }

  public Map<FieldType, Integer> getHitBdd() {
    return _hitBdd;
  }

  public Integer getFieldHitBdd(FieldType fieldType) {
    return _hitBdd.get(fieldType);
  }


  public int getPriority() {
    return _priority;
  }

  public String getPort() {
    return _port;
  }

  @Override
  public boolean equals(Object o) {
    if (o instanceof Rule) {
      Rule another = (Rule) o;
      return another._priority == _priority && another._port.equals(_port);
    }
    return false;
  }

  @Override
  public int compareTo(Rule a) {
    return a._priority - _priority;
  }
}
