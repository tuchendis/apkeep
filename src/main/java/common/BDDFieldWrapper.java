package common;

import apkeep.rules.FieldType;
import apkeep.utils.Parameters;
import jdd.bdd.BDD;

import java.util.Collection;
import java.util.LinkedList;

public abstract class BDDFieldWrapper {
    /**
     * the number of variables that field BDD needs.
     */
    public final static int protocolBits = 8;
    public final static int portBits = 16;
    public final static int ipBits = 32;
    public final static int mplsBits = 20;
    public final static int ip6Bits = 128;
    /**
     * for readability. In bdd:
     * 0 is the false node
     * 1 is the true node
     */
    public final static int BDDFalse = 0;
    public final static int BDDTrue = 1;

    BDD _aclBDD;
    FieldType _fieldType;

    public BDDFieldWrapper(FieldType fieldType) {
        this._aclBDD = new BDD(Parameters.BDD_TABLE_SIZE, 1000000);
        this._fieldType = fieldType;
    }

    public abstract int convertAclRule(ACLRule rule);

    public BDD getBDD()
    {
        return _aclBDD;
    }

    /**
     * @return the size of bdd (in bytes)
     */
    public long BDDSize() {
        return _aclBDD.getMemoryUsage();
    }

    public void DeclareVars(int[] vars, int bits) {
        for (int i = bits - 1; i >= 0; i--) {
            vars[i] = _aclBDD.createVar();
        }
    }

    /**
     * @param vars - a list of bdd nodes that we do not need anymore
     */
    public void DerefInBatch(int[] vars)
    {
        for(int i = 0; i < vars.length; i ++)
        {
            _aclBDD.deref(vars[i]);
        }
    }

    public void deref(int bdd)
    {
        _aclBDD.deref(bdd);
    }

    public int ref(int bdd)
    {
        return _aclBDD.ref(bdd);
    }

//    public int getFieldBdd(Fields field_name)
//    {
//        switch(field_name){
//            case dst_ip: return dstIPField;
//            default: return BDDFalse;
//        }
//    }

    /**
     * @param bddnodes - an array of bdd nodes
     * @return - the bdd node which is the AND of all input nodes
     * all temporary nodes are de-referenced.
     * the input nodes are not de-referenced.
     */
    public int AndInBatch(int [] bddnodes)
    {
        int tempnode = BDDTrue;
        for(int i = 0; i < bddnodes.length; i ++)
        {
            if(i == 0)
            {
                tempnode = bddnodes[i];
                _aclBDD.ref(tempnode);
            }else
            {
                if(bddnodes[i] == BDDTrue)
                {
                    // short cut, TRUE does not affect anything
                    continue;
                }
                if(bddnodes[i] == BDDFalse)
                {
                    // short cut, once FALSE, the result is false
                    // the current tempnode is useless now
                    _aclBDD.deref(tempnode);
                    tempnode = BDDFalse;
                    break;
                }
                int tempnode2 = _aclBDD.and(tempnode, bddnodes[i]);
                _aclBDD.ref(tempnode2);
                // do not need current tempnode
                _aclBDD.deref(tempnode);
                //refresh
                tempnode = tempnode2;
            }
        }
        return tempnode;
    }

    /**
     * already reference the new bdd node
     * @param bdd1
     * @param bdd2
     * @return
     */
    public int and(int bdd1, int bdd2)
    {
        return _aclBDD.ref(_aclBDD.and(bdd1, bdd2));
    }

    /**
     * @param bddnodes - an array of bdd nodes
     * @return - the bdd node which is the OR of all input nodes
     * all temporary nodes are de-referenced.
     * the input nodes are not de-referenced.
     */
    public int OrInBatch(int [] bddnodes)
    {
        int tempnode = BDDFalse;
        for(int i = 0; i < bddnodes.length; i ++)
        {
            if(i == 0)
            {
                tempnode = bddnodes[i];
                _aclBDD.ref(tempnode);
            }else
            {
                if(bddnodes[i] == BDDFalse)
                {
                    // short cut, FALSE does not affect anything
                    continue;
                }
                if(bddnodes[i] == BDDTrue)
                {
                    // short cut, once TRUE, the result is true
                    // the current tempnode is useless now
                    _aclBDD.deref(tempnode);
                    tempnode = BDDTrue;
                    break;
                }
                int tempnode2 = _aclBDD.or(tempnode, bddnodes[i]);
                _aclBDD.ref(tempnode2);
                // do not need current tempnode
                _aclBDD.deref(tempnode);
                //refresh
                tempnode = tempnode2;
            }
        }
        return tempnode;
    }

    /**
     * handle ref-count
     * @param bdd1
     * @param bdd2
     * @return
     */
    public int or(int bdd1, int bdd2) {
        // TODO Auto-generated method stub
        return _aclBDD.ref(_aclBDD.or(bdd1, bdd2));
    }

    // bdd1 and (not bdd2)
    public int diff(int bdd1, int bdd2)
    {
        int not2 = _aclBDD.ref(_aclBDD.not(bdd2));
        int diff = _aclBDD.ref(_aclBDD.and(bdd1, not2));
        _aclBDD.deref(not2);

        return diff;

    }
    /**
     * bdd1 <- bdd1 and (not bdd2)
     * @param bdd1
     * @param bdd2
     * @return
     */
    public int diffTo(int bdd1, int bdd2)
    {
        int res = diff(bdd1, bdd2);
        _aclBDD.deref(bdd1);
        return res;
    }
    /**
     * wrapper of BDD's orTo
     * @param bdd1
     * @param bdd2
     * @return
     */
    public int orTo(int bdd1, int bdd2)
    {
        return _aclBDD.orTo(bdd1, bdd2);
    }

    /**
     *
     * @param prefix -
     * @param vars - bdd variables used
     * @param bits - number of bits in the representation
     * @return a bdd node representing the predicate
     * e.g. for protocl, bits = 8, prefix = {1,0,1,0}, so the predicate is protocol[4]
     * and (not protocol[5]) and protocol[6] and (not protocol[7])
     */
    public int EncodePrefix(int [] prefix, int[] vars, int bits)
    {
        if(prefix.length == 0)
        {
            return BDDTrue;
        }

        int tempnode = BDDTrue;
        for(int i = 0; i < prefix.length; i ++)
        {
            if(i == 0){
                tempnode = EncodingVar(vars[bits - prefix.length + i], prefix[i]);
            }else
            {
                int tempnode2 = EncodingVar(vars[bits - prefix.length + i], prefix[i]);
                int tempnode3 = _aclBDD.and(tempnode, tempnode2);
                _aclBDD.ref(tempnode3);
                //do not need tempnode2, tempnode now
                //_aclBDD.deref(tempnode2);
                //_aclBDD.deref(tempnode);
                DerefInBatch(new int[]{tempnode, tempnode2});
                //refresh tempnode 3
                tempnode = tempnode3;
            }
        }
        return tempnode;
    }

    /**
     *
     * @param r - the range
     * @param vars - bdd variables used
     * @param bits - number of bits in the representation
     * @return the corresponding bdd node
     */
    public int ConvertRange(Range r, int [] vars, int bits)
    {

        LinkedList<int []> prefix = Utility.DecomposeInterval(r, bits);
        //System.out.println(vars.length);
        if(prefix.size() == 0)
        {
            return BDDTrue;
        }

        int tempnode = BDDTrue;
        for(int i = 0; i < prefix.size(); i ++)
        {
            if(i == 0)
            {
                tempnode = EncodePrefix(prefix.get(i), vars, bits);
            }else
            {
                int tempnode2 = EncodePrefix(prefix.get(i), vars, bits);
                int tempnode3 = _aclBDD.or(tempnode, tempnode2);
                _aclBDD.ref(tempnode3);
                DerefInBatch(new int[]{tempnode, tempnode2});
                tempnode = tempnode3;
            }
        }
        return tempnode;
    }

    /**
     * print out a graph for the bdd node var
     */
    public void PrintVar(int var)
    {
        if(_aclBDD.isValid(var))
        {
            _aclBDD.printDot(Integer.toString(var), var);
            System.out.println("BDD node " + var + " printed.");
        }else
        {
            System.err.println(var + " is not a valid BDD node!");
        }
    }

    /**
     * return the size of the bdd tree
     */
    public int getNodeSize(int bddnode)
    {
        int size = _aclBDD.nodeCount(bddnode);
        if(size == 0)
        {// this means that it is only a terminal node
            size ++;
        }
        return size;
    }

    public int getNodeSize(Collection<Integer> nodes)
    {
        int size = 0;
        for(int n : nodes)
        {
            size += getNodeSize(n);
        }
        return size;
    }

    /*
     * cleanup the bdd after usage
     */
    public void CleanUp()
    {
        _aclBDD.cleanup();
    }

    /***
     * var is a BDD variable
     * if flag == 1, return var
     * if flag == 0, return not var, the new bdd node is referenced.
     */
    public int EncodingVar(int var, int flag)
    {
        if (flag == 0)
        {
            int tempnode = _aclBDD.not(var);
            // no need to ref the negation of a variable.
            // the ref count is already set to maximal
            //_aclBDD.ref(tempnode);
            return tempnode;
        }
        if (flag == 1)
        {
            return var;
        }

        //should not reach here
        System.err.println("flag can only be 0 or 1!");
        return -1;
    }
}
