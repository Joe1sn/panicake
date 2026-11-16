/*
 * @Date: 2026-11-03 14:54:36
 * @LastEditors: joe1sn joe1sn23333@gmail.com
 * @LastEditTime: 2026-11-16 14:46:16
 * @FilePath: \panicake\src\main.cpp
 */
#include <iostream>
#include <Windows.h>

#include "exp/CVE_2023_21768/exp.hpp"
#include "exp/CVE_2023_28252/exp.hpp"
 // #include "exp/CVE_2026_40369/exp.hpp"
#include "exp/CVE_2021_1732/exp.hpp"
#include "exp/CVE_2021_40449/exp.hpp"

int main(int argc, char* argv[])
{
    SetConsoleOutputCP(CP_UTF8);   // 让控制台按 UTF-8 解释输出
    SetConsoleCP(CP_UTF8);         // 输入也按 UTF-8（可选）
    std::cout << "______           _           _        \n";
    std::cout << "| ___ \\         (_)         | |       \n";
    std::cout << "| |_/ /_ _ _ __  _  ___ __ _| | _____ \n";
    std::cout << "|  __/ _` | '_ \\| |/ __/ _` | |/ / _ \\\n";
    std::cout << "| | | (_| | | | | | (_| (_| |   <  __/\n";
    std::cout << "\\_|  \\__,_|_| |_|_|\\___\\__,_|_|\\_\\___|\n";
    if (argc != 2) {
        std::cout << "[!] userage: Panicake.exe <your vuln, like: cve-2021-1732>";
        return 0;
    }
    std::string cve = argv[1];
    if (cve == "cve-2021-1732")
        CVE_2021_1732::Exp();
    else if (cve == "cve-2021-40449")
        CVE_2021_40449::Exp();
    else if (cve == "cve-2023-21768")
        CVE_2023_21768::Exp();
    else if (cve == "cve-2023-28252")
        CVE_2023_28252::Exp();
    else if (cve == "-h" || cve == "--help") {
        std::cout << "[+] Supported:\n";
        std::cout << "[+]   cve-2021-1732\n";
        std::cout << "[+]   cve-2021-40449\n";
        std::cout << "[+]   cve-2023-21768\n";
        std::cout << "[+]   cve-2023-28252\n";
    }
    else {
        std::cout << "[!] Sorry, we don't have exploit for vuln" << cve << " yet\n";
        std::cout << "[!] maybe you can upload your exploit code to our exploit database:\n";
        std::cout << "[!] https://github.com/joe1sn/Panicake with `exploit` branch\n";
    }
    return 0;
}