// Copyright (c) 2020 G. Andrew Stone
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "stackitem.h"


VchStackType VchStack;

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
