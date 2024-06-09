package common;

import apkeep.rules.FieldType;

public class BDDProtocolWrapper extends BDDFieldWrapper {
    int[] _protocol;

    public BDDProtocolWrapper(FieldType fieldType) {
        super(fieldType);
        _protocol = new int[protocolBits];
        DeclareVars(_protocol, protocolBits);
    }

    @Override
    public int convertAclRule(ACLRule rule) {
        int protocolNode = BDDTrue;
        if(rule.protocolLower == null ||
                rule.protocolLower.equalsIgnoreCase("any")) {
            //do nothing, just a shortcut
        } else{
            Range r = ACLRule.convertProtocolToRange
                    (rule.protocolLower, rule.protocolUpper);
            protocolNode = ConvertRange(r, _protocol, protocolBits);
        }
        return protocolNode;
    }
}
