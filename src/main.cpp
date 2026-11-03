/*
 * @Date: 2026-11-03 14:54:36
 * @LastEditors: joe1sn joe1sn23333@gmail.com
 * @LastEditTime: 2026-11-03 15:02:27
 * @FilePath: \panicake\src\main.cpp
 */
#include <iostream>
#include <Windows.h>

 // #include "exp/CVE_2023_21768/exp.hpp"
  // #include "exp/CVE_2026_40369/exp.hpp"
#include "exp/CVE_2021_1732/exp.hpp"

int main()
{
    SetConsoleOutputCP(CP_UTF8);   // 让控制台按 UTF-8 解释输出
    SetConsoleCP(CP_UTF8);         // 输入也按 UTF-8（可选）
    // CVE_2023_21768::Exp();
    // CVE_2026_40369::Exp();
    CVE_2021_1732::Exp();
    return 0;
}