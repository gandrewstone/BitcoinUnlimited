// Copyright (c) 2020 G. Andrew Stone
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/stackitem.h"
#include "script/script.h"


VchStackType VchStack;

uint64_t StackItem::asUint64(bool requireMinimal) const
{
    if (isVch())
        return CScriptNum(vch, requireMinimal).getint();
    if (isBigNum())
    {
        if (n < 0_BN)
            throw BadOpOnType("Impossible conversion of negative BigNum to uint64");
        if (n >= 0x10000000000000000_BN)
            throw BadOpOnType("Impossible conversion of large BigNum to uint64");
        return n.asUint64();
    }
    throw BadOpOnType("Impossible conversion of stack item to uint64");
}


StackItem::operator bool() const
{
    switch (type)
    {
    case StackElementType::VCH:
        for (unsigned int i = 0; i < vch.size(); i++)
        {
            if (vch[i] != 0)
            {
                // Can be negative zero
                if (i == vch.size() - 1 && vch[i] == 0x80)
                    return false;
                return true;
            }
        }
        return false;
        break;
    case StackElementType::BIGNUM:
        return !(n == 0L);
        break;
    }

    throw BadOpOnType("Stack type cannot be cast to boolean");
}
