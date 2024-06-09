package common;

import apkeep.rules.FieldType;

public class BDDPortWrapper extends BDDFieldWrapper {
    int[] _port;

    public BDDPortWrapper(FieldType fieldType) {
        super(fieldType);
        _port = new int[portBits];
        DeclareVars(_port, portBits);
    }

    @Override
    public int convertAclRule(ACLRule rule) {
        int portNode = BDDTrue;
        Range r = null;
        if (_fieldType == FieldType.dstPort) {
            if(rule.destinationPortLower == null ||
                    rule.destinationPortLower.equalsIgnoreCase("any"))
            {
                // do nothing, just a shortcut
            }else{
                r = ACLRule.convertPortToRange(rule.destinationPortLower,
                        rule.destinationPortUpper);
            }
        } else {
            if(rule.sourcePortLower == null ||
                    rule.sourcePortLower.equalsIgnoreCase("any"))
            {
                //do nothing, just a shortcut
            }else{
                r = ACLRule.convertPortToRange(rule.sourcePortLower,
                        rule.sourcePortUpper);
            }
        }
        return portNode = ConvertRange(r, _port, portBits);
    }
}
