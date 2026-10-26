#include <iostream>
// #include "exp/CVE_2023_21768/exp.hpp"
#include "exp/CVE_2026_40369/exp.hpp"
using std::cout;

unsigned int io2num(unsigned int ioctl_num) {
    return ((ioctl_num ^ 0x220000) >> 2) & 0xfff;
}

int main()
{
    SetConsoleOutputCP(CP_UTF8);   // 让控制台按 UTF-8 解释输出
    SetConsoleCP(CP_UTF8);         // 输入也按 UTF-8（可选）
    // CVE_2023_21768::Exp();
    CVE_2026_40369::Exp();
    return 0;
}