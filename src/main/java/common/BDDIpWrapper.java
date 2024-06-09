package common;

import apkeep.rules.FieldType;

public class BDDIpWrapper extends BDDFieldWrapper {
    int[] _ip;

    public BDDIpWrapper(FieldType fieldType) {
        super(fieldType);
        _ip = new int[ipBits];
        DeclareVars(_ip, ipBits);
    }

    @Override
    public int convertAclRule(ACLRule rule) {
        int ipNode;
        if (_fieldType == FieldType.srcIp) {
            ipNode = ConvertIPAddress(rule.source, rule.sourceWildcard, _ip);
        } else {
            ipNode = ConvertIPAddress(rule.destination, rule.destinationWildcard, _ip);
        }
        return ipNode;
    }

    public int encodeIPPrefix(long ipaddr, int prefixlen)
    {
        int[] ipbin = Utility.CalBinRep(ipaddr, ipBits);
        int[] ipbinprefix = new int[prefixlen];
        for(int k = 0; k < prefixlen; k ++)
        {
            ipbinprefix[k] = ipbin[k + ipBits - prefixlen];
        }
        int entrybdd = EncodePrefix(ipbinprefix, _ip, ipBits);
        return entrybdd;
    }

    /**
     * @param IP address and mask
     * @return the corresponding bdd node
     */
    protected int ConvertIPAddress(String IP, String Mask, int[] vars)
    {
        int tempnode = BDDTrue;
        // case 1 IP = any
        if(IP == null || IP.equalsIgnoreCase("any"))
        {
            // return TRUE node
            return tempnode;
        }

        // binary representation of IP address
        int[] ipbin = Utility.IPBinRep(IP);
        // case 2 Mask = null
        if(Mask == null)
        {
            // no mask is working
            return EncodePrefix(ipbin, vars, ipBits);
        }else{
            int [] maskbin = Utility.IPBinRep(Mask);
            int numMasked = Utility.NumofNonZeros(maskbin);

            int [] prefix = new int[maskbin.length - numMasked];
            int [] varsUsed = new int[prefix.length];
            int ind = 0;
            for(int i = 0; i < maskbin.length; i ++)
            {
                if(maskbin[i] == 0)
                {
                    prefix[ind] = ipbin[i];
                    varsUsed[ind] = vars[i];
                    ind ++;
                }
            }

            return EncodePrefix(prefix, varsUsed, prefix.length);
        }

    }
}
