#pragma once
#define WIN32_LEAN_AND_MEAN
#include "Windows.h"
namespace CVE_2021_1732
{
    void arbitryRead0x10Size(ULONG_PTR pAddr, ULONG_PTR& valLow, ULONG_PTR& valHigh);
    bool Exp();
} // namespace CVE_2021_1732