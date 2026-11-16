/*
 * @Date: 2026-11-09 08:46:38
 * @LastEditors: joe1sn joe1sn23333@gmail.com
 * @LastEditTime: 2026-11-16 14:33:21
 * @FilePath: \panicake\exp\CVE_2023_28252\exp.hpp
 */
#pragma once
#include <string>
namespace CVE_2023_28252
{
    inline std::wstring tFileName;
    inline std::wstring tFilePath;
    inline std::wstring tLogFilePath;
    inline std::wstring tContainerPath;

    void blfParser(std::wstring filepath);
    void banner();
    void Exp();
} // namespace CVE_2023_28252