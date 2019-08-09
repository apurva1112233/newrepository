#ifdef __WATCOMC__ 
  #pragma enum int 
#endif 

#define  STRICT
#ifndef  UNICODE
#define  UNICODE
#endif
#ifndef  _UNICODE
#define  _UNICODE
#endif
#define  WINVER         0x0501
#define  _WIN32_IE      0x0600
#define  _WIN32_WINNT   0x0501
#define  NTDDI_VERSION  0x05010000

#include <tchar.h>
#include <stdarg.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sys\stat.h>
#include <io.h>
#include <fcntl.h>
#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <wininet.h>
#include <winldap.h>
#include "templatefiles.h"
#include "crcmodel.h"

#define  LENGTH(x)                 (sizeof (x)) / (sizeof (TCHAR))
#define  DEFAULT_NOTICE_CAPTION    TEXT("While using this asset (IBM or BYOD) for IBM business, I agree to the following terms of use.")
#define  DEFAULT_NOTICE_TEXT       TEXT("a. I am aware of IBM Security Policies and will comply with them.\r\n\r\nb. I fully understand my responsibility to comply with IBM’s software installation and acquisition guidance. So I will not install any unauthorized software on this machine.\r\n\r\nc. While installing or using open source software, I will comply with IBM’s Open Source Software usage Policies and Procedures.")
#define  WIPA_GENERAL_FAILURE      1
#define  WIPA_RECORD_NOCHANGE      -1
#define  BYTE_ORDER_MARK           0xFEFF
#define  BUFFER_INITIAL_ALLOCATION 2048
#define  BUFFER_REALLOC_INCREMENT  1024
#define  SECTION_NAMES_BUFFER_SIZE 65536
#define  BLOCK_SIZE                65536
#define  DEFAULT_DOWNLOAD_SERVER   TEXT("pokgsa.ibm.com")
#define  DEFAULT_SERVER_PATH       TEXT("/projects/w/wipa/web/")
#define  DEFAULT_DISPLAY_URL       TEXT("http://pokgsa.ibm.com/projects/w/wipa/web/wipaNotify.html?")
#define  DEFAULT_FILES_TO_PRESERVE 10
#define  CRC_EQUAL                 0
#define  CRC_NOT_EQUAL             1
#define  CRC_FILE_OPEN_ERROR       2
#define  CRC_FILE_READ_ERROR       3
#define  VARIABLE_TYPES_COUNT      5
#define  MULTIPART_BOUNDARY        "@@##$$bboouunnddaarryy@@##$$"
#define  WIPA_EVENT                TEXT("Workstation Installed Programs Auditor")

static WCHAR   g_pgmVersion[_MAX_PATH + 1];
static BOOL   g_is64bit = FALSE;
static WCHAR  g_dataDir[_MAX_PATH + 1];
static WCHAR  g_logfile[_MAX_PATH + 1] = TEXT("");
static WCHAR  g_uninTemplate[_MAX_PATH + 1];
static WCHAR  g_uninOutput[_MAX_PATH + 1];
static HANDLE g_hLogMsgMutex = NULL;
static UINT   g_uiOutputCodePage = CP_UTF8;
static DWORD  g_ScanSequenceNumber = 0;
static int    g_FilesToPreserve = DEFAULT_FILES_TO_PRESERVE;
static WCHAR  g_uninPublisherExclude[2048] = TEXT("");
static WCHAR  g_uninPublisherInclude[2048] = TEXT("");
static WCHAR  g_uninDisplayNameExclude[2048] = TEXT("");
static WCHAR  g_uninDisplayNameInclude[2048] = TEXT("");
static WCHAR  g_userPublisherExclude[2048] = TEXT("");
static WCHAR  g_userPublisherInclude[2048] = TEXT("");
static WCHAR  g_userDisplayNameExclude[2048] = TEXT("");
static WCHAR  g_userDisplayNameInclude[2048] = TEXT("");
static WCHAR  g_displayUrl[2000];
static int    g_productNumber = 0;
static BOOL   g_forgetScan = TRUE;
static WCHAR  g_previousIniFile[_MAX_PATH + 1];
static WCHAR  g_currentIniFile[_MAX_PATH + 1];
static WCHAR  g_uploadFileName[_MAX_PATH + 1];
static WCHAR  g_machineID[_MAX_PATH + 1 - 3]; /* Allow room for adding "_UX" to create file name */
static WCHAR  g_schtasksExePath[_MAX_PATH + 1];
static WCHAR  g_systemDirectory[_MAX_PATH + 1];

typedef enum tag_delta {Old, New, Mod, Del} Delta;
enum variableItemOption {USE_CURRENT, INSERT_AFTER_CURRENT};
typedef struct variableItem {
  WCHAR  *itemName;
  WCHAR  *itemValue;
  int    (*getItemValue)(WCHAR **);
  int    displayName;
  struct variableItem *pNextItem;
} VI, *PVI;
typedef struct variableType {
  WCHAR  *vtName;
  PVI    pVtFirstItem;
} VT, *PVT;

static VI firstUiItem = {NULL, NULL, NULL, 0, NULL},
          firstBpItem = {NULL, NULL, NULL, 0, NULL},
          firstBiItem = {NULL, NULL, NULL, 0, NULL},
          firstUsItem = {NULL, NULL, NULL, 0, NULL},
          firstSyItem = {NULL, NULL, NULL, 0, NULL},
          firstSpItem = {NULL, NULL, NULL, 0, NULL};
/**********************************************************************************/
/* In ISAM this structure is the head of eleven linked lists, one for each of the */
/* eleven source id's.  The addreses of the structures above will be filled in by */
/* code below.  Additional elements are added to the lists later, and are         */
/* obtained by calloc().                                                          */
/*                                                                                */
/* In WIPA only five of these source id's is supported, in order to be able to    */
/* substitute specifically requested values in the uninstall template.            */
/*                                                                                */
/* The firstUiItem is handled differently than the other structures, and is not   */
/* needed in the variableTypes array.                                             */
/**********************************************************************************/
static VT variableTypes[VARIABLE_TYPES_COUNT] = {{TEXT("%bluepages:"), NULL},
                                                 {TEXT("%bios:"), NULL},
                                                 {TEXT("%user:"), NULL},
                                                 {TEXT("%system:"), NULL},
                                                 {TEXT("%special:"), NULL}};

static int   GetPgmVersion(char *pgmName, WCHAR *pgmVersion);
static int   executeCmdHidden(LPWSTR cmd);
static int   uninstallInventory(WCHAR *template, FILE *myOut);
static int   initializeUnicodeIniFile(LPCWSTR pIniFilePath, LPCWSTR pInitialSectionName);
static void  addUninstallDeleteRecords(WCHAR *pIniFileSectionNames,
                                       WCHAR *template,
                                       FILE  *myOut,
                                       WCHAR *outputFilePath);
static int   processUninstallKey(HKEY   hKey,
                                 LPWSTR productKeyNameSuffix,
                                 LPWSTR pIniFileSectionNames,
                                 LPWSTR pProcessedTemplate,
                                 FILE   *myOut);
static void  removeSectionNameOrKey(WCHAR *pIniFileSectionNamesOrKeys, WCHAR *pSectionNameOrKey);
static int   substituteUninstallValues(WCHAR **pOutputString,
                                       WCHAR *inputString,
                                       WCHAR *outputFilePath,
                                       Delta dInitialValue);
static BOOL  copyWithRealloc(WCHAR **pBuffer,
                             DWORD *pLenBuffer,
                             DWORD targetOffset,
                             WCHAR *source,
                             DWORD lenSource);
static int   eraseFileWithErrorLogging(TCHAR *fileToErase);
static int   fileExists (TCHAR *fn, int *type);
static void  LogMsg(TCHAR *fmt, ...);
static void  clearItemQueueNamesAndValues(struct variableItem *variPtrFirst);
static int   uninstallScan(void);
static int   writeOutputString(WCHAR *wszOutput, FILE *fp, UINT uiFileCodePage);
static BOOL  isZeroLengthFile(WCHAR *filePath);
static int   renameFileWithErrorLogging(WCHAR *oldFilePath, WCHAR *newFilePath);
static int   insertItemQueueNameAndValue(struct variableItem     *variPtrIn,
                                         enum variableItemOption opt,
                                         WCHAR                   *newItemName,
                                         WCHAR                   *newItemValue,
                                         size_t                  forceValueLength,
                                         int                     (*newGetItemValue)(WCHAR **),
                                         int                     displayStringId);
static void  turnOffAttributes(WCHAR *fn);
static int   httpGetFile(TCHAR *server,
                         TCHAR *sourceFile,
                         TCHAR *localFile,
                         BOOL  secure);
static DWORD formatWindowsErrorMsg(TCHAR *msg);
static void  updateUrl(void);
static int   verifyCrc(LPCWSTR filePath, LPCWSTR fileCrc); 
static void  initializeGlobals(LPCWSTR wipaIni, LPCWSTR countryCode);
static void  processNoticeText(LPWSTR outText, LPCWSTR inText);
static void  substituteOneLine(WCHAR **pOutputString, WCHAR *inputString, WCHAR *iniFilePath);
static int   initUsNamesAndValues(void);
static int   initBiNamesAndValues(void);
static int   initBpNamesAndValues(void);
static int   initSpNamesAndValues(void);
static int   initSyNamesAndValues(void);
static BOOL  realtimeStatusCheck(WCHAR *rtUploadServer,
                                 WCHAR *rtUploadPort,
                                 WCHAR *rtStatusScript,
                                 BOOL  rtUploadSecure);
static DWORD formatWinErrMsg(WCHAR *msg);
static void  startMultipart(LPSTR buf,
                            DWORD bufSize,
                            DWORD *pDataLength);
static BOOL  addFileToMultipart(LPSTR   buf,
                                DWORD   bufSize,
                                DWORD   *pDataLength,
                                LPCWSTR name,
                                LPCWSTR fileName,
                                LPCWSTR filePath,
                                LPCSTR  bndry);
static BOOL  completeMultipart(LPSTR  buf,
                               DWORD  bufSize,
                               DWORD  *pDataLength,
                               LPCSTR bndry);
static int   postFileToServer(WCHAR *rtUploadServer,
                              WCHAR *rtUploadPort,
                              WCHAR *rtUploadScript,
                              BOOL  rtUploadSecure,
                              char  *fileBuf,
                              DWORD cgiDataLength,
                              char  *bndry,
                              WCHAR *outputFilePath);
static BOOL  uploadFile(WCHAR *rtUploadServer,
                        WCHAR *rtUploadPort,
                        WCHAR *rtUploadScript,
                        BOOL  rtUploadSecure,
                        WCHAR *fileName,
                        WCHAR *filePath);
static int   includeFileForRealtime(WCHAR *filePath, DWORD *fileSizeTotal);
static int   removeLeadingAndTrailingSpaces(WCHAR *buffer);
static void  allowRunOnBattery(int taskNumber);
static BOOL  createBatFile(WCHAR *batPath, WCHAR *batData);
static BOOL  productShouldBeDisplayed(WCHAR *publisher, WCHAR *displayName);
static void  preserveOutputFiles(int numberOfFiles);
static int   selfCheckScan(void);
static int  GetEmployeeCountryCode(WCHAR *countryCode);

int wmain(int argc, wchar_t **wargv)
{
  int              rc = 0;
  int              ft;
  WCHAR            *tempPtr;
  WCHAR            localAppdataDir[_MAX_PATH + 1];
  HRESULT          hResult;
  WCHAR            wipaIni[_MAX_PATH + 1];
  WCHAR            downloadServer[1024];
  WCHAR            serverFilePath[2048];
  WCHAR            serverFile[2048];
  WCHAR            tempDisplayUrl[2000] = TEXT("");
  DWORD            urlLength;
  WCHAR            exeDir[_MAX_PATH + 1];
  WCHAR            exeFile[_MAX_PATH + 1];
  WCHAR            exeFileCrc[32];
  WCHAR            newExeFile[_MAX_PATH + 1];
  WCHAR            wipaUpdFile[_MAX_PATH + 1];
  int              crcRc;
  WCHAR            defaultNoticeCaption[] = DEFAULT_NOTICE_CAPTION;
  WCHAR            defaultNoticeText[] = DEFAULT_NOTICE_TEXT;
  WCHAR            iniNoticeCaption[256];
  WCHAR            iniNoticeText[4096];
  WCHAR            noticeCaption[256];
  WCHAR            noticeText[4096];
  LONG             retcode;
  HKEY             hKey = NULL;
  DWORD            dataBufferSize, valueType;
  DWORD            dwDisposition;
  int              scansPerDay;
  WCHAR            startTime[8];
  WCHAR            scanTimes[4][8];
  WCHAR            parms[4096];
  SHELLEXECUTEINFO sei;
  int              i;
  WCHAR            wipaExePath[_MAX_PATH + 1];
  WCHAR            programFilesDirectory[_MAX_PATH + 1];
  DWORD            dwExitCode;
  BOOL             updateInProgress = FALSE;
  WCHAR            cmdExePath[_MAX_PATH + 1];
  WCHAR            uploadFiles[256];
  BOOL             wipainiUpload = FALSE;
  WCHAR            realtimeUploadServer[512] = TEXT("");
  WCHAR            realtimeUploadPort[16] = TEXT("");
  WCHAR            realtimeStatusScript[128] = TEXT("");
  WCHAR            realtimeUploadScript[128] = TEXT("");
  BOOL             realtimeUploadSecure = FALSE;
  int              selfCheckInterval;
  WCHAR            buf[2048];
  WCHAR            buf1[2048];
  WCHAR            validChars[] = TEXT("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
                                  TEXT("_."); /* "$%'`-@{}~!#()&^+,=[] " removed from list */
  DWORD            fileNameLen;
  BOOL             fileUploaded;
  WCHAR            wszUploaded[16];
  WCHAR            wipa0BatPath[_MAX_PATH + 1];
  WCHAR            wipa0BatData[4096];
  HANDLE           hev = NULL;
  WCHAR            ourEvent[64];
  TCHAR            dateBuf[81];
  time_t           currentTime;
  struct tm        then;
  time_t           now;
  double           secs;
  int              days;
  WCHAR            countryCode[10];
  
  /* Create an event to prevent more copies of us starting. */
  swprintf(ourEvent, LENGTH(ourEvent), TEXT("Global\\%s"), WIPA_EVENT);
  hev = CreateEvent(NULL, TRUE, FALSE, ourEvent);
  if ((hev == NULL) || (GetLastError() == ERROR_ALREADY_EXISTS)) {
    goto exitWIPA; /* Event could not be created, or already exists - just exit rc = 0 */
  }

  /* set a "random" random number seed for this thread */
  srand((unsigned)time(NULL));

  /* Determine if this is a 64 bit operating system */
#ifdef _WIN64
  g_is64bit = TRUE;
#else
  g_is64bit = FALSE;
  if (!(IsWow64Process(GetCurrentProcess(), &g_is64bit) && g_is64bit)) {
    g_is64bit = FALSE;
  }
#endif
  /* Setup the path to the System directory */
  if (0 == GetSystemDirectory(g_systemDirectory, sizeof g_systemDirectory)) {
    wcscpy(g_systemDirectory, TEXT("c:\\windows\\system32"));
  }
  /* If necessary, create our data directory. */
  hResult = SHGetFolderPath(NULL,
                            CSIDL_LOCAL_APPDATA,
                            NULL,
                            0,
                            localAppdataDir);
  if (SUCCEEDED(hResult)) {
    swprintf(g_dataDir, LENGTH(g_dataDir), TEXT("%s\\IBM"), localAppdataDir);
    if (!(fileExists(g_dataDir, &ft) && ft == TEXT('d'))) { /* the directory does not exist */
      if (!CreateDirectory(g_dataDir, NULL)) {
        rc = WIPA_GENERAL_FAILURE;
        goto exitWIPA;
      }
    }
    swprintf(g_dataDir, LENGTH(g_dataDir), TEXT("%s\\IBM\\WIPA"), localAppdataDir);
    if (!(fileExists(g_dataDir, &ft) && ft == TEXT('d'))) { /* the directory does not exist */
      if (!CreateDirectory(g_dataDir, NULL)) {
        rc = WIPA_GENERAL_FAILURE;
        goto exitWIPA;
      }
    }
  } else {
    rc = WIPA_GENERAL_FAILURE;
    goto exitWIPA;
  }

  /* Initialize paths to our data files. */
  swprintf(g_logfile, LENGTH(g_logfile), TEXT("%s\\wipa.log"), g_dataDir);
  GetPgmVersion(__argv[0], g_pgmVersion);
  LogMsg(TEXT("--- Start Run --- Version %s"), g_pgmVersion);
  swprintf(g_uninOutput, LENGTH(g_uninOutput), TEXT("%s\\wipa.out"), g_dataDir);
  swprintf(g_previousIniFile, LENGTH(g_previousIniFile), TEXT("%s-prev.ini"), g_uninOutput);
  swprintf(g_currentIniFile, LENGTH(g_currentIniFile), TEXT("%s-curr.ini"), g_uninOutput);
  swprintf(wipaIni, LENGTH(wipaIni), TEXT("%s\\wipa.ini"), g_dataDir);
  /* This name will be overridden with a name including the Machine ID, once */
  /* that is successfully read from the registry in initSpNamesAndValues().  */
  wcscpy(g_uploadFileName, TEXT("wipa.out"));

  /* Get the path to our executable directory. */
  if (0 != GetModuleFileName(NULL, exeFile, LENGTH(exeFile))) {
    wcscpy(exeDir, exeFile);
    tempPtr = wcsrchr(exeDir, TEXT('\\'));
    if (tempPtr != NULL) {
      *tempPtr = TEXT('\0');
    } else {
      rc = WIPA_GENERAL_FAILURE;
      LogMsg(TEXT("Cannot get path to executable directory."));
      goto exitWIPA;
    }
  } else {
    rc = WIPA_GENERAL_FAILURE;
    LogMsg(TEXT("Cannot get path to executable directory."));
    goto exitWIPA;
  }

  /* Initialize paths to files in our executable directory. */
  swprintf(g_uninTemplate, LENGTH(g_uninTemplate), TEXT("%s\\wipaunin.mif"), exeDir);

  /* Setup the path to schtasks.exe */
  wcscpy(g_schtasksExePath, g_systemDirectory);
  if (!PathAppend(g_schtasksExePath, TEXT("schtasks.exe"))) {
    rc = WIPA_GENERAL_FAILURE;
    LogMsg(TEXT("Cannot set path to schtasks.exe."));
    goto exitWIPA;
  }

  /* Download wipa.ini. */
  if (fileExists(wipaIni, &ft) && ft == TEXT('f')) { /* the ini file exists */
    if (0 == GetPrivateProfileString(TEXT("Parameters"),
                                     TEXT("DownloadServer"),
                                     DEFAULT_DOWNLOAD_SERVER,
                                     downloadServer,
                                     LENGTH(downloadServer),
                                     wipaIni)) {
      wcscpy(downloadServer, DEFAULT_DOWNLOAD_SERVER);
    }
    if (0 == GetPrivateProfileString(TEXT("Parameters"),
                                     TEXT("ServerFilePath"),
                                     DEFAULT_SERVER_PATH,
                                     serverFilePath,
                                     LENGTH(serverFilePath),
                                     wipaIni)) {
      wcscpy(serverFilePath, DEFAULT_SERVER_PATH);
    }
  } else {
    LogMsg(TEXT("File \"%s\" does not exist, using default values."), wipaIni);
    wcscpy(downloadServer, DEFAULT_DOWNLOAD_SERVER);
    wcscpy(serverFilePath, DEFAULT_SERVER_PATH);
  }
  swprintf(serverFile, LENGTH(serverFile), TEXT("%swipa.ini"), serverFilePath);
  if (0 != httpGetFile(downloadServer, serverFile, wipaIni, FALSE)) {
    LogMsg(TEXT("httpGetFile failed for \"%s\" from \"%s\", waiting 5 minutes for retry."), serverFile, downloadServer);
    Sleep(300000);
    if (0 != httpGetFile(downloadServer, serverFile, wipaIni, FALSE)) {
      LogMsg(TEXT("httpGetFile failed for \"%s\" from \"%s\", exiting."), serverFile, downloadServer);
      goto exitWIPA;
    }
  }
  if (!(fileExists(wipaIni, &ft) && ft == TEXT('f'))) { /* the ini file does not exist */
    LogMsg(TEXT("File \"%s\" does not exist, exiting."), wipaIni);
    rc = WIPA_GENERAL_FAILURE;
    goto exitWIPA;
  }

  /* Self update if necessary */
  if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_CURRENT_USER,
                                    TEXT("SOFTWARE\\IBM\\WIPA"),
                                    0L,
                                    KEY_READ | KEY_WRITE,
                                    &hKey)) {
    dataBufferSize = sizeof updateInProgress; /* set the size of the data buffer */
    if (ERROR_SUCCESS == RegQueryValueEx(hKey,
                                         TEXT("UpdateInProgress"),
                                         NULL,
                                         &valueType,
                                         (LPBYTE)&updateInProgress,
                                         &dataBufferSize)) {
      if (ERROR_SUCCESS != RegDeleteValue(hKey,
                                          TEXT("UpdateInProgress"))) {
        LogMsg(TEXT("Error deleting \"UpdateInProgress\" registry value."));
      }
    } else {
      updateInProgress = FALSE;
    }
    RegCloseKey(hKey);
  }
  if (8 == GetPrivateProfileString(TEXT("Parameters"),
                                   TEXT("ExeFileCrc"),
                                   TEXT(""),
                                   exeFileCrc,
                                   LENGTH(exeFileCrc),
                                   wipaIni)) {
    crcRc = verifyCrc(exeFile, exeFileCrc);
    if (crcRc == CRC_NOT_EQUAL) {
      if (updateInProgress) {
        LogMsg(TEXT("Exe file CRCs differ, but an update loop was detected."));
      } else {
        LogMsg(TEXT("Exe file CRCs differ, the program will be updated."));
        swprintf(serverFile, LENGTH(serverFile), TEXT("%swipa.exe"), serverFilePath);
        swprintf(newExeFile, LENGTH(newExeFile), TEXT("%s.new"), exeFile);
        if (0 == httpGetFile(downloadServer, serverFile, newExeFile, FALSE)) {
          swprintf(serverFile, LENGTH(serverFile), TEXT("%swipaupd.exe"), serverFilePath);
          swprintf(wipaUpdFile, LENGTH(wipaUpdFile), TEXT("%s\\wipaupd.exe"), exeDir);
          if (0 == httpGetFile(downloadServer, serverFile, wipaUpdFile, FALSE)) {
            retcode = RegCreateKeyEx(HKEY_CURRENT_USER,
                                     TEXT("SOFTWARE\\IBM\\WIPA"),
                                     0L,
                                     NULL,
                                     REG_OPTION_NON_VOLATILE,
                                     KEY_READ | KEY_WRITE,
                                     NULL,
                                     &hKey,
                                     &dwDisposition);
            if (retcode == ERROR_SUCCESS) {
              updateInProgress = TRUE;
              retcode = RegSetValueEx(hKey,
                                      TEXT("UpdateInProgress"),
                                      0L,
                                      REG_DWORD,
                                      (LPBYTE)&updateInProgress,
                                      sizeof(DWORD));
              if (retcode != ERROR_SUCCESS) {
                LogMsg(TEXT("RegSetValueEx for UpdateInProgress failed with return code %l"), retcode);
              }
              RegCloseKey(hKey);
            } else {
              LogMsg(TEXT("RegCreateKeyEx for WIPA failed with return code %l"), retcode);
            }
            LogMsg(TEXT("Running \"%s\" and exiting to allow new version to run."), wipaUpdFile);
            ShellExecute(NULL,
                         NULL,
                         wipaUpdFile,
                         NULL,
                         NULL,
                         SW_HIDE);
            goto exitWIPA;
          } else {
            LogMsg(TEXT("httpGetFile failed for \"%s\" from \"%s\", using current version."), serverFile, downloadServer);
          }
        } else {
          LogMsg(TEXT("httpGetFile failed for \"%s\" from \"%s\", using current version."), serverFile, downloadServer);
        }
      }
    }
  }

  /* If uploads are enabled, then verify that the upload server is ready */
  if (0 < GetPrivateProfileString(TEXT("Parameters"),
                                  TEXT("UploadFiles"),
                                  TEXT(""),
                                  uploadFiles,
                                  LENGTH(uploadFiles),
                                  wipaIni)) {
    if (_wcsicmp(uploadFiles, TEXT("yes")) == 0) {
      wipainiUpload = TRUE;
      
      // Get the users Country Code from bluepages and build the geo specific ini file section names for the CC specific values
      GetEmployeeCountryCode(countryCode);
      if (wcslen(countryCode) == 0) {
        LogMsg(TEXT("Could not get users countryCode from bluepages"));
        rc = WIPA_GENERAL_FAILURE;
        goto exitWIPA;
      }
      LogMsg(TEXT("Users Geo: <%s>"), countryCode);

      swprintf(buf, LENGTH(buf), TEXT("CountryCode_%s"),countryCode);

      // REALTIMEUPLOADSERVER - Try to get the geo specific value first if not found then use the default
      realtimeUploadServer[0] = TEXT('\0');
      if (GetPrivateProfileString(buf, TEXT("REALTIMEUPLOADSERVER"), TEXT(""), realtimeUploadServer, LENGTH(realtimeUploadServer), wipaIni) > 0) {
        LogMsg(TEXT("Using [%s] REALTIMEUPLOADSERVER= from wipa.ini"),buf);
      } else {
        if (0 == GetPrivateProfileString(TEXT("Parameters"), TEXT("REALTIMEUPLOADSERVER"), TEXT(""), realtimeUploadServer, LENGTH(realtimeUploadServer), wipaIni)) {
          LogMsg(TEXT("Could not read [Parameters] RealtimeUploadServer= from wipa.ini, exiting."));
          rc = WIPA_GENERAL_FAILURE;
          goto exitWIPA;
        }
      } 
        
      // REALTIMEUPLOADPORT - Try to get the geo specific value first if not found then use the default
      realtimeUploadPort[0] = TEXT('\0');
      if (GetPrivateProfileString(buf, TEXT("REALTIMEUPLOADPORT"), TEXT(""), realtimeUploadPort, LENGTH(realtimeUploadPort), wipaIni) > 0) {
        LogMsg(TEXT("Using [%s] REALTIMEUPLOADPORT= from wipa.ini"),buf);
      } else {
        if (0 == GetPrivateProfileString(TEXT("Parameters"), TEXT("REALTIMEUPLOADPORT"), TEXT(""), realtimeUploadPort, LENGTH(realtimeUploadPort), wipaIni)) {
          LogMsg(TEXT("Could not read [Parameters] RealtimeUploadPort= from wipa.ini, exiting."));
          rc = WIPA_GENERAL_FAILURE;
          goto exitWIPA;
        }
      }

      // REALTIMESTATUSSCRIPT - Try to get the geo specific value first if not found then use the default
      realtimeStatusScript[0] = TEXT('\0');
      if (GetPrivateProfileString(buf, TEXT("REALTIMESTATUSSCRIPT"), TEXT(""), realtimeStatusScript, LENGTH(realtimeStatusScript), wipaIni) > 0) {
        LogMsg(TEXT("Using [%s] REALTIMESTATUSSCRIPT= from wipa.ini"),buf);
      } else {
        if (0 == GetPrivateProfileString(TEXT("Parameters"), TEXT("REALTIMESTATUSSCRIPT"), TEXT(""), realtimeStatusScript, LENGTH(realtimeStatusScript), wipaIni)) {
          LogMsg(TEXT("Could not read [Parameters] REALTIMESTATUSSCRIPT= from wipa.ini, exiting."));
          rc = WIPA_GENERAL_FAILURE;
          goto exitWIPA;
        }
      } 

      // REALTIMEUPLOADSCRIPT - Try to get the geo specific value first if not found then use the default
      realtimeUploadScript[0] = TEXT('\0');
      if (GetPrivateProfileString(buf, TEXT("REALTIMEUPLOADSCRIPT"), TEXT(""), realtimeUploadScript, LENGTH(realtimeUploadScript), wipaIni) > 0) {
        LogMsg(TEXT("Using [%s] REALTIMEUPLOADSCRIPT= from wipa.ini"),buf);
      } else {
        if (0 == GetPrivateProfileString(TEXT("Parameters"), TEXT("REALTIMEUPLOADSCRIPT"), TEXT(""), realtimeUploadScript, LENGTH(realtimeUploadScript), wipaIni)) {
          LogMsg(TEXT("Could not read [Parameters] REALTIMEUPLOADSCRIPT= from wipa.ini, exiting."));
          rc = WIPA_GENERAL_FAILURE;
          goto exitWIPA;
        }
      } 

      // REALTIMEUPLOADSECURE - Try to get the geo specific value first if not found then use the default
      buf1[0] = TEXT('\0');
      if (0 == GetPrivateProfileString(buf, TEXT("REALTIMEUPLOADSECURE"), TEXT(""), buf1, LENGTH(buf1), wipaIni)) {
        GetPrivateProfileString(TEXT("Parameters"), TEXT("REALTIMEUPLOADSECURE"), TEXT(""), buf1, LENGTH(buf1), wipaIni);
      } 
      if ((_wcsicmp(buf1, TEXT("yes")) == 0) || (_wcsicmp(buf1, TEXT("1")) == 0)) {
        realtimeUploadSecure = TRUE;
      }

      if (0 != GetPrivateProfileString(TEXT("Parameters"),
                                       TEXT("SELFCHECKINTERVAL"),
                                       TEXT("14"),
                                       buf,
                                       LENGTH(buf),
                                       wipaIni)) {
        selfCheckInterval = _wtoi(buf);
      } else {
        LogMsg(TEXT("Could not read selfCheckInterval from wipa.ini, using default: 14 days"));
        selfCheckInterval = 14;
      }

      if (!realtimeStatusCheck(realtimeUploadServer,
                               realtimeUploadPort,
                               realtimeStatusScript,
                               realtimeUploadSecure)) {
        LogMsg(TEXT("Could not verify upload status with \"%s\", waiting up to 10 minutes for retry."), realtimeUploadServer);
        Sleep(((rand() % 540) + 60) * 1000); /* wait between 1 and 10 minutes */
        if (!realtimeStatusCheck(realtimeUploadServer,
                                 realtimeUploadPort,
                                 realtimeStatusScript,
                                 realtimeUploadSecure)) {
          LogMsg(TEXT("Could not verify upload status with \"%s\", exiting."), realtimeUploadServer);
          rc = WIPA_GENERAL_FAILURE;
          goto exitWIPA;
        }
      }
    } else {
      wipainiUpload = FALSE;
    }
  } else {
    wipainiUpload = FALSE;
  }

  /* Download wipaunin.mif if possible */
  swprintf(serverFile, LENGTH(serverFile), TEXT("%swipaunin.mif"), serverFilePath);
  if (0 != httpGetFile(downloadServer, serverFile, g_uninTemplate, FALSE)) {
    LogMsg(TEXT("httpGetFile failed for \"%s\" from \"%s\"."), serverFile, downloadServer);
  }

  /* Initialize global variables from wipa.ini */
  initializeGlobals(wipaIni, countryCode);

  /* Set the scan sequence number for this scan */
  g_ScanSequenceNumber = GetPrivateProfileInt(TEXT("Info"), TEXT("ScanSequenceNumber"), 0, g_previousIniFile);
  g_ScanSequenceNumber++;

  /* Set up to be able to substitute for the ISAM machine ID in the uninstall template. */
  for (i = 0; i < VARIABLE_TYPES_COUNT; i++) {
    if (wcscmp(TEXT("%bluepages:"), variableTypes[i].vtName) == 0)
      variableTypes[i].pVtFirstItem = &firstBpItem;
    else if (wcscmp(TEXT("%bios:"), variableTypes[i].vtName) == 0)
      variableTypes[i].pVtFirstItem = &firstBiItem;
    else if (wcscmp(TEXT("%user:"), variableTypes[i].vtName) == 0)
      variableTypes[i].pVtFirstItem = &firstUsItem;
    else if (wcscmp(TEXT("%system:"), variableTypes[i].vtName) == 0)
      variableTypes[i].pVtFirstItem = &firstSyItem;
    else if (wcscmp(TEXT("%special:"), variableTypes[i].vtName) == 0)
      variableTypes[i].pVtFirstItem = &firstSpItem;
  }
  /***********************************************************************************/
  /* Initialize the list of User variable names we support, and if the user has      */
  /* previously registered the machine, get the values entered at the previous       */
  /* registration.                                                                   */
  /***********************************************************************************/
  rc = initUsNamesAndValues();
  if (rc != 0) {
    LogMsg(TEXT("Failure initializing User variable names and values."));
    rc = WIPA_GENERAL_FAILURE;
    goto exitWIPA;
  }
  /***********************************************************************************/
  /* Initialize the list of Bios variable names we support, and if the user has      */
  /* previously registered the machine, get the values determined at the previous    */
  /* registration.                                                                   */
  /***********************************************************************************/
  rc = initBiNamesAndValues();
  if (rc != 0) {
    LogMsg(TEXT("Failure initializing Bios variable names and values."));
    rc = WIPA_GENERAL_FAILURE;
    goto exitWIPA;
  }
  /***********************************************************************************/
  /* Initialize the list of Bluepages variable names we support, and if the user has */
  /* previously registered the machine, get the values determined at the previous    */
  /* registration.                                                                   */
  /***********************************************************************************/
  rc = initBpNamesAndValues();
  if (rc != 0) {
    LogMsg(TEXT("Failure initializing Bluepages variable names and values."));
    rc = WIPA_GENERAL_FAILURE;
    goto exitWIPA;
  }
  /***********************************************************************************/
  /* Initialize the list of System variable names we support, and if the user has    */
  /* previously registered the machine, get the values determined at the previous    */
  /* registration.                                                                   */
  /***********************************************************************************/
  rc = initSyNamesAndValues();
  if (rc != 0) {
    LogMsg(TEXT("Failure initializing System variable names and values."));
    rc = WIPA_GENERAL_FAILURE;
    goto exitWIPA;
  }
  /***********************************************************************************/
  /* Initialize the list of Special variable names we support, and if the user has   */
  /* previously registered the machine, get the values determined at the previous    */
  /* registration.                                                                   */
  /***********************************************************************************/
  rc = initSpNamesAndValues();
  if (rc != 0) {
    LogMsg(TEXT("Failure initializing Special variable names and values."));
    rc = WIPA_GENERAL_FAILURE;
    goto exitWIPA;
  }
  if (g_machineID[0] != TEXT('\0')) {
    swprintf(g_uploadFileName, LENGTH(g_uploadFileName), TEXT("%s_UX"), g_machineID);
    /* Substitute "_" for any character in the upload file name that would */
    /* not be valid in a file name.                                        */
    fileNameLen = wcslen(g_uploadFileName);
    for (i = 0; i < fileNameLen; i++) {
      if (wcschr(validChars, g_uploadFileName[i]) == NULL) {
        g_uploadFileName[i] = TEXT('_');
      }
    }
  } else {
    /* If we cannot get the ISAM machine ID, we do not upload files. */
    wipainiUpload = FALSE;
  }
  /* If our output was not uploaded after the last scan, but our output will be uploaded */
  /* this time, then we remove the previous ini file to force full output to be created. */
  if (wipainiUpload && (fileExists(g_previousIniFile, &ft) && ft == TEXT('f'))) {
    /* The default for "Uploaded" is "No" */
    if (0 == GetPrivateProfileString(TEXT("Info"),
                                     TEXT("Uploaded"),
                                     TEXT("No"),
                                     wszUploaded,
                                     LENGTH(wszUploaded),
                                     g_previousIniFile)) {
      wcscpy(wszUploaded, TEXT("No"));
    }
    if (_wcsicmp(wszUploaded, TEXT("No")) == 0) {
      /* Erasing the previous ini file will force a new initial scan. */
      eraseFileWithErrorLogging(g_previousIniFile);
      g_ScanSequenceNumber = 1;
    }
  }

  /* Do the scan */
  rc = uninstallScan();

  /* If we are to upload our output and we haven't decided that this scan should be */
  /* forgotten ...                                                                  */
  if (wipainiUpload && !g_forgetScan) {
    fileUploaded = uploadFile(realtimeUploadServer,
                              realtimeUploadPort,
                              realtimeUploadScript,
                              realtimeUploadSecure,
                              g_uploadFileName,
                              g_uninOutput);
    if (!fileUploaded) {
      LogMsg(TEXT("uploadFile failed for \"%s\" to \"%s\", waiting up to 10 minutes for retry."), g_uploadFileName, realtimeUploadServer);
      Sleep(((rand() % 540) + 60) * 1000); /* wait between 1 and 10 minutes */
      fileUploaded = uploadFile(realtimeUploadServer,
                                realtimeUploadPort,
                                realtimeUploadScript,
                                realtimeUploadSecure,
                                g_uploadFileName,
                                g_uninOutput);
      if (!fileUploaded) {
        LogMsg(TEXT("uploadFile failed for \"%s\" to \"%s\", scan will be forgotten."), g_uploadFileName, realtimeUploadServer);
      }
    }
    if (fileUploaded) {
      /* If the upload was successful */
      WritePrivateProfileString(TEXT("Info"),
                                TEXT("Uploaded"),
                                TEXT("Yes"),
                                g_currentIniFile);

      currentTime = time(NULL);
      wcsftime(dateBuf, sizeof dateBuf, TEXT("%Y%m%d"), localtime(&currentTime));
      WritePrivateProfileString(TEXT("Info"),
                                TEXT("UploadDate"),
                                dateBuf,
                                g_currentIniFile);
    } else {
      g_forgetScan = TRUE;
    }
  } else {
    // Check to see we need to do a self check upload
    if (0 != GetPrivateProfileString(TEXT("Info"),
                                     TEXT("UploadDate"),
                                     TEXT(""),
                                     dateBuf,
                                     LENGTH(dateBuf),
                                     g_previousIniFile)) {
      
    } else {
      LogMsg(TEXT("Could not read upLoadDate from %s"), g_previousIniFile);
      wcscpy(dateBuf,TEXT("20150701"));
    }
    memset(&then,0,sizeof(then));
    memset(&buf,0,sizeof(buf));
    wcsncpy(buf,dateBuf,4);
    then.tm_year = _wtoi(buf) - 1900;

    memset(&buf,0,sizeof(buf));
    wcsncpy(buf,&dateBuf[4],2);
    then.tm_mon = _wtoi(buf) - 1;

    memset(&buf,0,sizeof(buf));
    wcsncpy(buf,&dateBuf[6],2);
    then.tm_mday = _wtoi(buf);

    mktime(&then);
    time(&now);
    secs = difftime(now,mktime(&then));
    days = secs / 86400;
    if (days >= selfCheckInterval) {
      LogMsg(TEXT("Need to send a Self Check Record"));
      rc = selfCheckScan();
      if (rc == 0) {
        fileUploaded = uploadFile(realtimeUploadServer,
                                  realtimeUploadPort,
                                  realtimeUploadScript,
                                  realtimeUploadSecure,
                                  g_uploadFileName,
                                  g_uninOutput);
        if (!fileUploaded) {
          LogMsg(TEXT("selfCheck uploadFile failed"));
        }
        if (fileUploaded) {
          /* If the upload was successful */
          currentTime = time(NULL);
          wcsftime(dateBuf, sizeof dateBuf, TEXT("%Y%m%d"), localtime(&currentTime));
          WritePrivateProfileString(TEXT("Info"),
                                    TEXT("UploadDate"),
                                    dateBuf,
                                    g_previousIniFile);
        }
      }
    }
  }
  
  if (g_forgetScan) {
    /* If we are forgetting the scan, either because we found no changes, or we      */
    /* found changes but the upload of data failed, then erase the current ini file. */ 
    if (fileExists(g_currentIniFile, &ft) && ft == TEXT('f')) {
      eraseFileWithErrorLogging(g_currentIniFile);
    }
  } else {
    /* Otherwise the scan was successful so erase the previous ini file and rename the current one. */
    if (fileExists(g_previousIniFile, &ft) && ft == TEXT('f')) {
      eraseFileWithErrorLogging(g_previousIniFile);
    }
    if (fileExists(g_currentIniFile, &ft) && ft == TEXT('f')) {
      renameFileWithErrorLogging(g_currentIniFile, g_previousIniFile);
    }
    /* Preserve scan output files */
    preserveOutputFiles(g_FilesToPreserve);
    /* If newly installed producte were found, encode the URL and display the web page */
    if ((rc == 0) && (g_productNumber > 0)) {
      urlLength = LENGTH(tempDisplayUrl);
      if (InternetCanonicalizeUrl(g_displayUrl,
                                  tempDisplayUrl,
                                  &urlLength,
                                  0)) {
        /* We need to open the URL using the Windows Scheduler in order to run the browser */
        /* as a normal user rather than as an administrator.                               */
        LogMsg(TEXT("Opening URL \"%s\"."), tempDisplayUrl);
        /* Setup the path to cmd.exe */
        wcscpy(cmdExePath, g_systemDirectory);
        if (PathAppend(cmdExePath, TEXT("cmd.exe"))) {
          swprintf(wipa0BatPath, LENGTH(wipa0BatPath), TEXT("%s\\wipa0.bat"), g_dataDir);
          swprintf(wipa0BatData, LENGTH(wipa0BatData), TEXT("start \"\" \"%s\"\n"), tempDisplayUrl);
          if (createBatFile(wipa0BatPath, wipa0BatData)) {
            for (i = 1; i <= 3; i++) {
              switch (i) {
              case 1:
                swprintf(parms,
                         LENGTH(parms),
                         TEXT("/Create /TN WIPA0 /TR \"%s /C '%s\\wipa0.bat'\" /SC ONCE /ST 23:59 /F"),
                         cmdExePath, g_dataDir);
                break;

              case 2:
                swprintf(parms, LENGTH(parms), TEXT("/Run /TN WIPA0"));
                break;

              case 3:
                swprintf(parms, LENGTH(parms), TEXT("/Delete /TN WIPA0 /F"));
                break;
              }
              ZeroMemory(&sei, sizeof(SHELLEXECUTEINFO));
              sei.cbSize = sizeof(SHELLEXECUTEINFO);
              sei.fMask = SEE_MASK_FLAG_NO_UI | SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_DDEWAIT;
              sei.lpFile = g_schtasksExePath;
              sei.lpParameters = parms;
              sei.lpDirectory = g_systemDirectory;
              sei.nShow = SW_HIDE;
              if (ShellExecuteEx(&sei)) {
                WaitForSingleObject(sei.hProcess, INFINITE);
                if (GetExitCodeProcess(sei.hProcess, &dwExitCode)) {
                  if (dwExitCode != 0) {
                    LogMsg(TEXT("Schtasks.exe exit code = %lu"), dwExitCode);
                    if (i < 3) {
                      LogMsg(TEXT("Could not display web page."));
                      if (i == 1) {
                        CloseHandle(sei.hProcess);
                        break;
                      }
                    }
                  }
                }
                CloseHandle(sei.hProcess);
              } else {
                if (i < 3) {
                  LogMsg(TEXT("Could not display web page."));
                  if (i == 1) {
                    break;
                  }
                }
              }
              /* Wait 1 second befor running schtasks.exe again */
              Sleep(1000);
              if (i == 1) {
                allowRunOnBattery(0); /* Modify the scheduled task to allow running on battery */
              }
            }
          } else {
            LogMsg(TEXT("Cannot create \"%s\", the product list cannot be shown."), wipa0BatPath);
          }
        } else {
          LogMsg(TEXT("Cannot set path to cmd.exe, the product list cannot be shown."));
        }
      } else {
        LogMsg(TEXT("The URL \"%s\" could not be encoded, the product list cannot be shown."), g_displayUrl);
      }
    }
  }

  /* Setup the legal agreement caption and text */
  if (0 == GetPrivateProfileString(TEXT("Parameters"),
                                   TEXT("NoticeCaption"),
                                   TEXT(""),
                                   iniNoticeCaption,
                                   LENGTH(iniNoticeCaption),
                                   wipaIni)) {
    wcscpy(noticeCaption, defaultNoticeCaption);
  } else {
    wcscpy(noticeCaption, iniNoticeCaption);
  }
  if (0 == GetPrivateProfileString(TEXT("Parameters"),
                                   TEXT("NoticeText"),
                                   TEXT(""),
                                   iniNoticeText,
                                   LENGTH(iniNoticeText),
                                   wipaIni)) {
    wcscpy(noticeText, defaultNoticeText);
  } else {
    processNoticeText(noticeText, iniNoticeText);
  }
  retcode = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                         TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
                         0L,
                         KEY_READ | KEY_WRITE | KEY_WOW64_64KEY,
                         &hKey);
  if (retcode == ERROR_SUCCESS) {
    retcode = RegSetValueEx(hKey,
                            TEXT("LegalNoticeCaption"),
                            0L,
                            REG_SZ,
                            (LPBYTE)noticeCaption,
                            (wcslen(noticeCaption) + 1) * sizeof(WCHAR));
    if (retcode == ERROR_SUCCESS) {
      retcode = RegSetValueEx(hKey,
                              TEXT("LegalNoticeText"),
                              0L,
                              REG_SZ,
                              (LPBYTE)noticeText,
                              (wcslen(noticeText) + 1) * sizeof(WCHAR));
      if (retcode != ERROR_SUCCESS) {
        LogMsg(TEXT("RegSetValueEx for LegalNoticeText failed with return code %l"), retcode);
      }
    } else {
      LogMsg(TEXT("RegSetValueEx for LegalNoticeCaption failed with return code %l"), retcode);
    }
    RegCloseKey(hKey);
  } else {
    LogMsg(TEXT("RegOpenKeyEx for Winlogon failed with return code %l"), retcode);
  }

  /* Schedule wipa.exe to run as administrator */
  scansPerDay = GetPrivateProfileInt(TEXT("Parameters"),
                                     TEXT("ScansPerDay"),
                                     2,
                                     wipaIni);
  if ((scansPerDay > 4) || (scansPerDay < 1)) {
    LogMsg(TEXT("ScansPerDay value of %d is invalid, set to 2"), scansPerDay);
    scansPerDay = 2;
  }
  switch (scansPerDay) {
  case 1:
    wcscpy(scanTimes[0], TEXT("16:00"));
    break;

  case 2:
    wcscpy(scanTimes[0], TEXT("10:00"));
    wcscpy(scanTimes[1], TEXT("16:00"));
    break;

  case 3:
    wcscpy(scanTimes[0], TEXT("10:00"));
    wcscpy(scanTimes[1], TEXT("13:00"));
    wcscpy(scanTimes[2], TEXT("16:00"));
    break;

  case 4:
    wcscpy(scanTimes[0], TEXT("10:00"));
    wcscpy(scanTimes[1], TEXT("12:00"));
    wcscpy(scanTimes[2], TEXT("14:00"));
    wcscpy(scanTimes[3], TEXT("16:00"));
    break;
  }
  /* Setup the path to the Program Files Directory */
  hResult = SHGetFolderPath(NULL,
                            CSIDL_PROGRAM_FILES,
                            NULL,
                            0,
                            programFilesDirectory);
  if (FAILED(hResult)) {
    /* Could not determine the WIPA program directory. */
    LogMsg(TEXT("Could not determine the WIPA program directory."));
  } else {
    wcscpy(wipaExePath, programFilesDirectory);
    if (!PathAppend(wipaExePath, TEXT("IBM\\WIPA\\wipa.exe"))) {
      /* Could not setup wipa.exe path. */
      LogMsg(TEXT("Could not setup wipa.exe path."));
    } else {
      for (i = 1; i <= 4; i++) { /* Maximum scans per day is 4 */
        if (i <= scansPerDay) {
          wcscpy(startTime, scanTimes[i - 1]);
          swprintf(parms, LENGTH(parms), TEXT("/Create /TN WIPA%d /TR \"'%s'\" /SC WEEKLY /D MON,TUE,WED,THU,FRI /ST %s /IT /RL HIGHEST /F"), i, wipaExePath, startTime);
        } else {
          swprintf(parms, LENGTH(parms), TEXT("/Delete /TN WIPA%d /F"), i);
        }
        ZeroMemory(&sei, sizeof(SHELLEXECUTEINFO));
        sei.cbSize = sizeof(SHELLEXECUTEINFO);
        sei.fMask = SEE_MASK_FLAG_NO_UI | SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_DDEWAIT;
        sei.lpFile = g_schtasksExePath;
        sei.lpParameters = parms;
        sei.lpDirectory = g_systemDirectory;
        sei.nShow = SW_HIDE;
        if (ShellExecuteEx(&sei)) {
          WaitForSingleObject(sei.hProcess, INFINITE);
          if (GetExitCodeProcess(sei.hProcess, &dwExitCode)) {
            if (dwExitCode == 0) {
              Sleep(1000); /* Wait one second before modifying the scheduled task */
              allowRunOnBattery(i); /* Modify the scheduled task to allow running on battery */
            } else {
              if (i <= scansPerDay) { /* Only record error if scheduling, not if removing */
                LogMsg(TEXT("Schtasks.exe exit code = %lu"), dwExitCode);
                /* Cannot schedule tasks. */
                LogMsg(TEXT("Could not schedule wipa.exe to run."));
              }
            }
          }
          CloseHandle(sei.hProcess);
        } else {
          /* Cannot schedule tasks. */
          LogMsg(TEXT("Could not schedule wipa.exe to run."));
        }
      }
    }
  }

exitWIPA:
  if (hev != NULL) {
    CloseHandle(hev);
  }
  LogMsg(TEXT("--- End Run ---"));
  return rc;
}

/****************************************************************************/
/* executeCmdHidden: execute command hidden and wait for completion.        */
/* Inputs   : command                                                       */
/* Outputs  : return code                                                   */
/****************************************************************************/
int executeCmdHidden(LPWSTR cmd)
{
/*-- Local Variables ------------------------------------------------------*/
  DWORD                dwExitCode = STILL_ACTIVE;
  DWORD                dwRc;
  STARTUPINFO          si;
  PROCESS_INFORMATION  pi;
/*-- Code -----------------------------------------------------------------*/

  memset(&si, 0, sizeof(STARTUPINFO));
  memset(&pi, 0, sizeof(PROCESS_INFORMATION));
  si.cb = sizeof(STARTUPINFO);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  if (CreateProcess(NULL,
                    cmd,
                    NULL,
                    NULL,
                    FALSE,
                    CREATE_NEW_CONSOLE,
                    NULL,
                    NULL,
                    &si,
                    &pi)) {
    CloseHandle(pi.hThread);
    dwExitCode = STILL_ACTIVE;
    while (dwExitCode == STILL_ACTIVE) {
      dwRc = WaitForSingleObject(pi.hProcess, 1000);
      if (dwRc == WAIT_OBJECT_0) {
        dwRc = GetExitCodeProcess(pi.hProcess, &dwExitCode);
      }
    }
    CloseHandle(pi.hProcess);
  } else {
    dwExitCode = GetLastError();
  }
  return (int)dwExitCode;
} /* end executeCmdHidden */

//
//
//
int selfCheckScan(void)
{
  int    rc = 0;
  int    ft;
  HANDLE fp;
  FILE   *fp2 = NULL;
  WCHAR  tempFN[_MAX_PATH + 1];
  LPWSTR pwszBuffer;
  WCHAR  *pProcessedTemplate = NULL;
  WCHAR  *pProcessedTemplate2 = NULL;
  struct variableItem *variPtr;
  time_t  currentTime;
  WCHAR  dateBuf[80];
  WCHAR  buf[80];

  swprintf(tempFN, LENGTH(tempFN), TEXT("%s.tmp"), g_uninOutput);
  if (fileExists(tempFN, &ft) && ft == TEXT('f')) {              /* The file exists */
    SetFileAttributes(tempFN, FILE_ATTRIBUTE_NORMAL);
    _wremove(tempFN);
  }
  if (fileExists(g_uninOutput, &ft) && ft == TEXT('f')) {
    eraseFileWithErrorLogging(g_uninOutput);
  }

  fp2 = _wfopen(tempFN, TEXT("wb"));
  if (fp2 == NULL) {
    LogMsg(TEXT("selfCheckScan: Could not open %s for write."), tempFN);
    rc = WIPA_GENERAL_FAILURE;
    goto exitselfCheckScan;
  }
  fp = openTemplateFile(g_uninTemplate, g_uiOutputCodePage);
  if (fp == NULL) {
    fclose(fp2);
    LogMsg(TEXT("selfCheckScan: Could not open \"%s\" for read using code page %d."), g_uninTemplate, g_uiOutputCodePage);
    rc = WIPA_GENERAL_FAILURE;
    goto exitselfCheckScan;
  }
  
  clearItemQueueNamesAndValues(&firstUiItem);
  variPtr = &firstUiItem;
  rc = insertItemQueueNameAndValue(variPtr,
                                   USE_CURRENT,
                                   TEXT("KeyName"),
                                   TEXT("selfCheck"),
                                   0,
                                   NULL,
                                   0);
  if (rc != 0) { goto exitselfCheckScan; }
  currentTime = time(NULL);
  wcsftime(dateBuf, sizeof dateBuf, TEXT("%Y%m%d"), localtime(&currentTime));
  swprintf(buf, sizeof(buf), L"WIPA_Self_Check_%s", dateBuf);
  rc = insertItemQueueNameAndValue(variPtr,
                                   INSERT_AFTER_CURRENT,
                                   TEXT("DisplayName"),
                                   buf,
                                   0,
                                   NULL,
                                   0);
  if (rc == 0) {
    variPtr = variPtr->pNextItem;
  } else {
    goto exitselfCheckScan;
  }
  rc = insertItemQueueNameAndValue(variPtr,
                                   INSERT_AFTER_CURRENT,
                                   TEXT("DisplayVersion"),
                                   g_pgmVersion,
                                   0,
                                   NULL,
                                   0);
  if (rc == 0) {
    variPtr = variPtr->pNextItem;
  } else {
    goto exitselfCheckScan;
  }
  rc = insertItemQueueNameAndValue(variPtr,
                                   INSERT_AFTER_CURRENT,
                                   TEXT("Publisher"),
                                   TEXT("IBM"),
                                   0,
                                   NULL,
                                   0);
  if (rc == 0) {
    variPtr = variPtr->pNextItem;
  } else {
    goto exitselfCheckScan;
  }
  
  while ((pwszBuffer = readTemplateFileLine(fp))) {
    substituteOneLine(&pProcessedTemplate, pwszBuffer, NULL); /* substitute values for place holders in the template */
    if (pProcessedTemplate == NULL) {
      LogMsg(TEXT("selfCheckScan: substituteOneLine() failed."));
      rc = WIPA_GENERAL_FAILURE;
      goto exitselfCheckScan;
    }
    substituteUninstallValues(&pProcessedTemplate2,pProcessedTemplate,TEXT(""),New);
    if (pProcessedTemplate2 == NULL) {
      LogMsg(TEXT("selfCheckScan: substituteUninstallValues() failed."));
      rc = WIPA_GENERAL_FAILURE;
      goto exitselfCheckScan;
    }
    writeOutputString(pProcessedTemplate2, fp2, g_uiOutputCodePage); /* write out new line to end of file */
    free(pwszBuffer);
    free(pProcessedTemplate);
    free(pProcessedTemplate2);
  }
  closeTemplateFile(fp);
  fclose(fp2);
  if (isZeroLengthFile(tempFN)) {
    eraseFileWithErrorLogging(tempFN);
  } else {
    /* copy the file */
    if (CopyFile(tempFN, g_uninOutput, FALSE)) {
      eraseFileWithErrorLogging(tempFN);
    } else {
      rc = WIPA_GENERAL_FAILURE;
    }
  }

exitselfCheckScan:
  return rc;
}


int uninstallScan(void)
{
  int    rc = 0;
  int    ft;
  HANDLE fp;
  FILE   *fp2 = NULL;
  WCHAR  tempFN[_MAX_PATH + 1];
  BOOL   foundSubstitutionStrings, outputThisLine;
  LPWSTR pwszBuffer;

  swprintf(tempFN, LENGTH(tempFN), TEXT("%s.tmp"), g_uninOutput);
  if (fileExists(tempFN, &ft) && ft == TEXT('f')) {              /* The file exists */
    SetFileAttributes(tempFN, FILE_ATTRIBUTE_NORMAL);
    _wremove(tempFN);
  }
  if (fileExists(g_uninOutput, &ft) && ft == TEXT('f')) {
    eraseFileWithErrorLogging(g_uninOutput);
  }

  fp2 = _wfopen(tempFN, TEXT("wb"));
  if (fp2 == NULL) {
    LogMsg(TEXT("uninstallScan: Could not open %s for write."), tempFN);
    rc = WIPA_GENERAL_FAILURE;
    goto exitUninstallScan;
  }
  fp = openTemplateFile(g_uninTemplate, g_uiOutputCodePage);
  if (fp == NULL) {
    fclose(fp2);
    LogMsg(TEXT("uninstallScan: Could not open \"%s\" for read using code page %d."), g_uninTemplate, g_uiOutputCodePage);
    rc = WIPA_GENERAL_FAILURE;
    goto exitUninstallScan;
  }
  foundSubstitutionStrings = FALSE;
  while ((pwszBuffer = readTemplateFileLine(fp))) {
    outputThisLine = TRUE;
    if (!foundSubstitutionStrings && (wcsstr(pwszBuffer, TEXT("%uninstall:")) != NULL)) {
      outputThisLine = FALSE;
      foundSubstitutionStrings = TRUE;
      rc = uninstallInventory(pwszBuffer, fp2);
    }
    if (outputThisLine) {
      writeOutputString(pwszBuffer, fp2, g_uiOutputCodePage); /* write out new line to end of file */
    }
    free(pwszBuffer);
  }
  closeTemplateFile(fp);
  fclose(fp2);
  if (isZeroLengthFile(tempFN)) {
    eraseFileWithErrorLogging(tempFN);
  } else {
    /* copy the file */
    if (CopyFile(tempFN, g_uninOutput, FALSE)) {
      eraseFileWithErrorLogging(tempFN);
    } else {
      rc = WIPA_GENERAL_FAILURE;
    }
  }

exitUninstallScan:
  return rc;
}

int uninstallInventory(WCHAR *template, FILE *myOut)
{
  int    rc = 0;
  int    ft;
  HKEY   hKey;
  WCHAR  *pProcessedTemplate = NULL;
  WCHAR  currScanSeq[16];
  WCHAR  *pIniFileSectionNames = NULL;
  REGSAM samDesired = 0;
  WCHAR  keyName[2048];
  WCHAR  productKeyNameSuffix[16];

  substituteOneLine(&pProcessedTemplate, template, NULL); /* substitute values for place holders in the template */
  if (pProcessedTemplate == NULL) {
    LogMsg(TEXT("uninstallInventory: Processing of template failed."));
    rc = WIPA_GENERAL_FAILURE;
    goto exitUninstallInventory;
  }
  swprintf(currScanSeq, LENGTH(currScanSeq), TEXT("%lu"), g_ScanSequenceNumber);
  /* erase the "current" ini file if it exists, since it should only exist if a previous */
  /* instance of this program was terminated abnormally.                                 */
  if (fileExists(g_currentIniFile, &ft) && ft == TEXT('f')) {
    eraseFileWithErrorLogging(g_currentIniFile);
  }
  if (0 != initializeUnicodeIniFile(g_currentIniFile, TEXT("Info"))) {
    LogMsg(TEXT("uninstallInventory: Could not initialize current ini file."));
    if (fileExists(g_currentIniFile, &ft) && ft == TEXT('f')) {
      eraseFileWithErrorLogging(g_currentIniFile);
    }
    rc = WIPA_GENERAL_FAILURE;
    goto exitUninstallInventory;
  }
  WritePrivateProfileString(TEXT("Info"),
                            TEXT("ScanSequenceNumber"),
                            currScanSeq,
                            g_currentIniFile);
  if (fileExists(g_previousIniFile, &ft) && ft == TEXT('f')) {
    pIniFileSectionNames = calloc(SECTION_NAMES_BUFFER_SIZE, sizeof(WCHAR));
    if (pIniFileSectionNames == NULL) {
      LogMsg(TEXT("uninstallInventory: Could not obtain storage for section names."));
      rc = WIPA_GENERAL_FAILURE;
      goto exitUninstallInventory;
    }
    if (0 == GetPrivateProfileSectionNames(pIniFileSectionNames,
                                           SECTION_NAMES_BUFFER_SIZE,
                                           g_previousIniFile)) {
      LogMsg(TEXT("uninstallInventory: %s is not a valid ini file, removing."), g_previousIniFile);
      eraseFileWithErrorLogging(g_previousIniFile);
    }
  }
  samDesired = KEY_READ;
  wcscpy(keyName, TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"));
  if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                                    keyName,
                                    0,
                                    samDesired,
                                    &hKey)) {
    productKeyNameSuffix[0] = TEXT('\0');
    rc = processUninstallKey(hKey,
                             productKeyNameSuffix,
                             pIniFileSectionNames,
                             pProcessedTemplate,
                             myOut);
    RegCloseKey(hKey);
    if (rc != 0) {
      goto exitUninstallInventory;
    }
  }
  wcscpy(keyName, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"));
  if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_CURRENT_USER,
                                    keyName,
                                    0,
                                    samDesired,
                                    &hKey)) {
    wcscpy(productKeyNameSuffix, TEXT("-CU"));
    rc = processUninstallKey(hKey,
                             productKeyNameSuffix,
                             pIniFileSectionNames,
                             pProcessedTemplate,
                             myOut);
    RegCloseKey(hKey);
    if (rc != 0) {
      goto exitUninstallInventory;
    }
  }
  if (g_is64bit) { /* This is a 64 bit version of Windows */
    samDesired = KEY_READ | KEY_WOW64_64KEY;
    wcscpy(keyName, TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"));
    if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                                      keyName,
                                      0,
                                      samDesired,
                                      &hKey)) {
      wcscpy(productKeyNameSuffix, TEXT("-64"));
      rc = processUninstallKey(hKey,
                               productKeyNameSuffix,
                               pIniFileSectionNames,
                               pProcessedTemplate,
                               myOut);
      RegCloseKey(hKey);
      if (rc != 0) {
        goto exitUninstallInventory;
      }
    }
    wcscpy(keyName, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"));
    if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_CURRENT_USER,
                                      keyName,
                                      0,
                                      samDesired,
                                      &hKey)) {
      wcscpy(productKeyNameSuffix, TEXT("-CU64"));
      rc = processUninstallKey(hKey,
                               productKeyNameSuffix,
                               pIniFileSectionNames,
                               pProcessedTemplate,
                               myOut);
      RegCloseKey(hKey);
      if (rc != 0) {
        goto exitUninstallInventory;
      }
    }
  }
  addUninstallDeleteRecords(pIniFileSectionNames, pProcessedTemplate, myOut, g_uninOutput);
  /* Moved ISAM code to remove the old and rename the new INI file from here to wmain */
exitUninstallInventory:
  if (pProcessedTemplate != NULL) {
    free(pProcessedTemplate);
  }
  return rc;
}

int initializeUnicodeIniFile(LPCWSTR pIniFilePath, LPCWSTR pInitialSectionName)
{
  int   rc = WIPA_GENERAL_FAILURE;
  int   rc2 = 0;
  WCHAR iniInit[] = {BYTE_ORDER_MARK,
                     TEXT('['),
                     TEXT('%'),
                     TEXT('s'),
                     TEXT(']'),
                     TEXT('\r'),
                     TEXT('\n'),
                     0};
  WCHAR buf[512];
  FILE  *fp = NULL;

  if (LENGTH(buf) >= (LENGTH(iniInit) - 2 + wcslen(pInitialSectionName))) {
    /* Initialize an ini file as a Unicode file */
    fp = _wfopen(pIniFilePath, TEXT("wb"));
    if (fp != NULL) {
      swprintf(buf, LENGTH(buf), iniInit, pInitialSectionName);
      rc2 = fputws(buf, fp);
      fclose(fp);
      if (rc2 >= 0) {
        rc = 0;
      }
    } else {
      LogMsg(TEXT("initializeUnicodeIniFile: Could not open \"%s\" for write."), pIniFilePath);
    }
  } else {
    LogMsg(TEXT("initializeUnicodeIniFile: Invalid section name was passed for initialization of \"%s\"."), pIniFilePath);
  }
  return rc;
}

void addUninstallDeleteRecords(WCHAR *pIniFileSectionNames,
                               WCHAR *template,
                               FILE  *myOut,
                               WCHAR *outputFilePath)
{
  WCHAR               *tempPtr;
  WCHAR               *pBuf = NULL;
  struct variableItem *variPtr;

  if (pIniFileSectionNames != NULL) {
    if (NULL != wcsstr(template, TEXT("%UpdateType%"))) {
      for (tempPtr = pIniFileSectionNames; tempPtr[0] != TEXT('\0'); tempPtr += (wcslen(tempPtr) + 1)) {
        if ((tempPtr[0] != TEXT(' ')) && (_wcsicmp(tempPtr, TEXT("Info")) != 0)) {
          clearItemQueueNamesAndValues(&firstUiItem);
          /* Initialize the Variable Item structures for the one Uninstall variable that we support. */
          variPtr = &firstUiItem;
          if (0 != insertItemQueueNameAndValue(variPtr,
                                               USE_CURRENT,
                                               TEXT("KeyName"),
                                               tempPtr,
                                               0,
                                               NULL,
                                               0)) {
            LogMsg(TEXT("addUninstallDeleteRecords: Failed to create delete record for \"%s\"."), tempPtr);
            continue;
          }
          if (0 == substituteUninstallValues(&pBuf,
                                             template,
                                             outputFilePath,
                                             Del)) {
            writeOutputString(pBuf, myOut, g_uiOutputCodePage); /* write out new line to end of file */
            g_forgetScan = FALSE;
            free(pBuf);
          }
        }
      }
    }
  }
  clearItemQueueNamesAndValues(&firstUiItem);
}

int processUninstallKey(HKEY   hKey,
                        LPWSTR productKeyNameSuffix,
                        LPWSTR pIniFileSectionNames,
                        LPWSTR pProcessedTemplate,
                        FILE   *myOut)
{
  int                 rc = 0;
  WCHAR               *subkeyName = NULL;
  DWORD               dwIndex, nSubkeys, nSubkeyNameLen;
  DWORD               dwIndex2;
  DWORD               retCode;
  HKEY                hSubKey;
  DWORD               rcREV;
  DWORD               dataBufferSize, valueType;
  WCHAR               displayName[2048];
  WCHAR               publisher[2048];
  WCHAR               parentKeyName[2048];
  WCHAR               releaseType[2048];
  WCHAR               szValue[2048];
  WCHAR               valueName[2048];
  DWORD               valueNameLength;
  WCHAR               buf[2048];
  DWORD               dwValue;
  WCHAR               *tempPtr;
  struct variableItem *variPtr;
  WCHAR               *pBuf2 = NULL;
  WCHAR               *wcstokState = NULL;

  retCode = RegQueryInfoKey(hKey,
                            NULL,
                            NULL,
                            NULL,
                            &nSubkeys,
                            &nSubkeyNameLen,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL);
  if (retCode != ERROR_SUCCESS) {
    rc = WIPA_GENERAL_FAILURE;
    goto exitProcessUninstallKey;
  }
  subkeyName = (WCHAR *)calloc(nSubkeyNameLen + wcslen(productKeyNameSuffix) + 1, sizeof(WCHAR));
  if (subkeyName == NULL) {
    rc = WIPA_GENERAL_FAILURE;
    goto exitProcessUninstallKey;
  }
  for (dwIndex = 0; dwIndex < nSubkeys; dwIndex++) {
    retCode = RegEnumKey(hKey, dwIndex, subkeyName, nSubkeyNameLen + 1);
    if (retCode == ERROR_SUCCESS) {
      retCode = RegOpenKeyEx(hKey,
                             subkeyName,
                             0,
                             KEY_READ,
                             &hSubKey);
      if (retCode == ERROR_SUCCESS) {
        dataBufferSize = sizeof displayName; /* set the size of the data buffer */
        retCode = RegQueryValueEx(hSubKey,
                                  TEXT("DisplayName"),
                                  NULL,
                                  &valueType,
                                  (LPBYTE)displayName,
                                  &dataBufferSize);
        if ((retCode == ERROR_SUCCESS) &&
            (displayName[0] != TEXT('\0'))) {
          if (0 < removeLeadingAndTrailingSpaces(displayName)) {
            /* We don't include any item which does not have a DisplayName value */
            dataBufferSize = sizeof parentKeyName; /* set the size of the data buffer */
            retCode = RegQueryValueEx(hSubKey,
                                      TEXT("ParentKeyName"),
                                      NULL,
                                      &valueType,
                                      (LPBYTE)parentKeyName,
                                      &dataBufferSize);
            if ((retCode != ERROR_SUCCESS) ||
                (parentKeyName[0] == TEXT('\0'))) {
              /* We don't include any item which has a ParentKeyName value */
              dataBufferSize = sizeof releaseType; /* set the size of the data buffer */
              retCode = RegQueryValueEx(hSubKey,
                                        TEXT("ReleaseType"),
                                        NULL,
                                        &valueType,
                                        (LPBYTE)releaseType,
                                        &dataBufferSize);
              if ((retCode != ERROR_SUCCESS) ||
                  ((_wcsicmp(releaseType, TEXT("Security Update")) != 0) &&
                   (_wcsicmp(releaseType, TEXT("Update Rollup")) != 0) &&
                   (_wcsicmp(releaseType, TEXT("Hotfix")) != 0) &&
                   (_wcsicmp(releaseType, TEXT("Service Pack")) != 0))) {
                /* We don't include any item which has a ReleaseType value */
                /* which indicates that the product is an update           */
                dataBufferSize = sizeof publisher; /* set the size of the data buffer */
                retCode = RegQueryValueEx(hSubKey,
                                          TEXT("Publisher"),
                                          NULL,
                                          &valueType,
                                          (LPBYTE)publisher,
                                          &dataBufferSize);
                if (retCode == ERROR_SUCCESS) {
                  removeLeadingAndTrailingSpaces(publisher);
                } else {
                  publisher[0] = TEXT('\0');
                }
                /* Always include the ISAM record, regardless of includes/excludes */
                if (_wcsicmp(displayName, TEXT("IBM Standard Asset Manager")) != 0) {
                  if (g_uninPublisherExclude[0] != TEXT('\0')) {
                    if (publisher[0] != TEXT('\0')) {
                      wcscpy(szValue, publisher);
                      CharLower(szValue);
                      wcscpy(buf, g_uninPublisherExclude);
                      CharLower(buf);
                      tempPtr = wcstok(buf, TEXT("|"), &wcstokState);
                      while (tempPtr != NULL) {
                        if (wcsstr(szValue, tempPtr) != NULL) { /* This publisher should be excluded */
                          break;
                        }
                        tempPtr = wcstok(NULL, TEXT("|"), &wcstokState);
                      }
                      if (tempPtr != NULL) { /* This publisher should be excluded */
                        RegCloseKey(hSubKey);
                        continue;
                      }
                    }
                  } else if (g_uninPublisherInclude[0] != TEXT('\0')) {
                    if (publisher[0] == TEXT('\0')) {
                      RegCloseKey(hSubKey);
                      continue;
                    }
                    wcscpy(szValue, publisher);
                    CharLower(szValue);
                    wcscpy(buf, g_uninPublisherInclude);
                    CharLower(buf);
                    tempPtr = wcstok(buf, TEXT("|"), &wcstokState);
                    while (tempPtr != NULL) {
                      if (wcsstr(szValue, tempPtr) != NULL) {
                        break;
                      }
                      tempPtr = wcstok(NULL, TEXT("|"), &wcstokState);
                    }
                    if (tempPtr == NULL) { /* This publisher should not be included */
                      RegCloseKey(hSubKey);
                      continue;
                    }
                  }
                  if (g_uninDisplayNameExclude[0] != TEXT('\0')) {
                    wcscpy(szValue, displayName);
                    CharLower(szValue);
                    wcscpy(buf, g_uninDisplayNameExclude);
                    CharLower(buf);
                    tempPtr = wcstok(buf, TEXT("|"), &wcstokState);
                    while (tempPtr != NULL) {
                      if (wcsstr(szValue, tempPtr) != NULL) { /* This display name should be excluded */
                        break;
                      }
                      tempPtr = wcstok(NULL, TEXT("|"), &wcstokState);
                    }
                    if (tempPtr != NULL) { /* This display name should be excluded */
                      RegCloseKey(hSubKey);
                      continue;
                    }
                  } else if (g_uninDisplayNameInclude[0] != TEXT('\0')) {
                    wcscpy(szValue, displayName);
                    CharLower(szValue);
                    wcscpy(buf, g_uninDisplayNameInclude);
                    CharLower(buf);
                    tempPtr = wcstok(buf, TEXT("|"), &wcstokState);
                    while (tempPtr != NULL) {
                      if (wcsstr(szValue, tempPtr) != NULL) {
                        break;
                      }
                      tempPtr = wcstok(NULL, TEXT("|"), &wcstokState);
                    }
                    if (tempPtr == NULL) { /* This display name should not be included */
                      RegCloseKey(hSubKey);
                      continue;
                    }
                  }
                }
                clearItemQueueNamesAndValues(&firstUiItem);
                /* Initialize the Variable Item structures for the Uninstall variables that we support. */
                variPtr = &firstUiItem;
                /* For the uninstall scan, the "KeyName" value must always be first. */
                /* Ensure the key name is unique by appending the suffix that was    */
                /* passed to us.                                                     */
                wcscat(subkeyName, productKeyNameSuffix);
                rc = insertItemQueueNameAndValue(variPtr,
                                                 USE_CURRENT,
                                                 TEXT("KeyName"),
                                                 subkeyName,
                                                 0,
                                                 NULL,
                                                 0);
                if (rc != 0) {
                  goto exitProcessUninstallKey;
                }
                rc = insertItemQueueNameAndValue(variPtr,
                                                 INSERT_AFTER_CURRENT,
                                                 TEXT("DisplayName"),
                                                 displayName,
                                                 0,
                                                 NULL,
                                                 0);
                if (rc == 0) {
                  variPtr = variPtr->pNextItem;
                } else {
                  goto exitProcessUninstallKey;
                }
                rc = insertItemQueueNameAndValue(variPtr,
                                                 INSERT_AFTER_CURRENT,
                                                 TEXT("Publisher"),
                                                 publisher,
                                                 0,
                                                 NULL,
                                                 0);
                if (rc == 0) {
                  variPtr = variPtr->pNextItem;
                } else {
                  goto exitProcessUninstallKey;
                }
                rcREV = ERROR_SUCCESS;
                for (dwIndex2 = 0; rcREV == ERROR_SUCCESS; dwIndex2++) {
                  ZeroMemory(valueName, sizeof valueName);
                  valueNameLength = LENGTH(valueName);
                  rcREV = RegEnumValue(hSubKey, 
                                       dwIndex2, 
                                       valueName,
                                       &valueNameLength,
                                       NULL,
                                       &valueType,
                                       NULL,
                                       NULL);
                  if (rcREV == ERROR_SUCCESS) {
                    /* We have already handled "DisplayName" and "Publisher", */
                    /* and we don't want to handle the unnamed value ...      */
                    if ((valueName[0] != TEXT('\0')) &&
                        (_wcsicmp(valueName, TEXT("DisplayName")) != 0) &&
                        (_wcsicmp(valueName, TEXT("Publisher")) != 0)) {
                      if ((valueType == REG_DWORD) ||
                          (valueType == REG_SZ) ||
                          (valueType == REG_EXPAND_SZ)) {
                        if (valueType == REG_DWORD) {
                          dataBufferSize = sizeof dwValue; /* set the size of the data buffer */
                          retCode = RegQueryValueEx(hSubKey,
                                                    valueName,
                                                    NULL,
                                                    &valueType,
                                                    (LPBYTE)&dwValue,
                                                    &dataBufferSize);
                          if (retCode == ERROR_SUCCESS) {
                            swprintf(szValue, LENGTH(szValue), TEXT("%lu"), dwValue);
                          }
                        } else {
                          dataBufferSize = sizeof szValue; /* set the size of the data buffer */
                          retCode = RegQueryValueEx(hSubKey,
                                                    valueName,
                                                    NULL,
                                                    &valueType,
                                                    (LPBYTE)szValue,
                                                    &dataBufferSize);
                        }
                        if (retCode == ERROR_SUCCESS) {
                          removeLeadingAndTrailingSpaces(szValue);
                          rc = insertItemQueueNameAndValue(variPtr,
                                                           INSERT_AFTER_CURRENT,
                                                           valueName,
                                                           szValue,
                                                           0,
                                                           NULL,
                                                           0);
                          if (rc == 0) {
                            variPtr = variPtr->pNextItem;
                          } else {
                            goto exitProcessUninstallKey;
                          }
                        }
                      }
                    }
                  }
                }
                removeSectionNameOrKey(pIniFileSectionNames, subkeyName);
                if (0 == substituteUninstallValues(&pBuf2,
                                                   pProcessedTemplate,
                                                   g_uninOutput,
                                                   Old)) {
                  writeOutputString(pBuf2, myOut, g_uiOutputCodePage);
                  g_forgetScan = FALSE;
                  free(pBuf2);
                  pBuf2 = NULL;
                }
              }
            }
          }
        }
        RegCloseKey(hSubKey);
      }
    }
  }
  free(subkeyName);
  subkeyName = NULL;
exitProcessUninstallKey:
  return rc;
}

void removeSectionNameOrKey(WCHAR *pIniFileSectionNamesOrKeys, WCHAR *pSectionNameOrKey)
{
  WCHAR *tempPtr;

  if (pIniFileSectionNamesOrKeys != NULL) {
    for (tempPtr = pIniFileSectionNamesOrKeys; tempPtr[0] != TEXT('\0'); tempPtr += (wcslen(tempPtr) + 1)) {
      if (_wcsicmp(tempPtr, pSectionNameOrKey) == 0) {
        tempPtr[0] = TEXT(' ');
        break;
      }
    }
  }
}

/****************************************************************************/
/* substituteUninstallValues: Scan one line for %uninstall:variable% place  */
/*                 holders, substituting the actual values from the         */
/*                 variable item structures.                                */
/* Inputs        : inputString, the string into which substitutions are to  */
/*               : be made                                                  */
/* Outputs       : outputString, the string with values substituted for     */
/*               : place holders                                            */
/****************************************************************************/
int  substituteUninstallValues(WCHAR **pOutputString,
                               WCHAR *inputString,
                               WCHAR *outputFilePath,
                               Delta dInitialValue)
{
  WCHAR  *pBuf = NULL;
  WCHAR  *pBuf2 = NULL;
  DWORD  lenBuf = 0;
  DWORD  lenBuf2 = 0;
  WCHAR  *varStrStart;
  WCHAR  *varStrEnd;
  WCHAR  *tempPtr;
  int    tokenLength;
  struct variableItem *variPtr;
  WCHAR  vtName[] = TEXT("%uninstall:");
  WCHAR  updateType[12] = TEXT("");
  Delta  d = dInitialValue;
  WCHAR  prevScanSeq[16];
  WCHAR  currScanSeq[16];
  int    rc = 0;
  WCHAR  *keyName = NULL;
  WCHAR  buf3[1024];
  BOOL   firstMatch;
  WCHAR  *substitutions[3][2] = {{TEXT("%CurrScanSeq%"), NULL},
                                 {TEXT("%PrevScanSeq%"), NULL},
                                 {TEXT("%UpdateType%"), NULL}};
  int    i;
  BOOL   foundKeyName = FALSE;
  WCHAR  *pIniFileSectionKeyNames = NULL;

  substitutions[0][1] = currScanSeq;
  substitutions[1][1] = prevScanSeq;
  substitutions[2][1] = updateType;
  *pOutputString = NULL;
  if (d != Del) {
    d = Old;
  }
  if (0 == GetPrivateProfileString(TEXT("Info"),
                                   TEXT("ScanSequenceNumber"),
                                   TEXT("0"),
                                   prevScanSeq,
                                   LENGTH(prevScanSeq),
                                   g_previousIniFile)) {
    wcscpy(prevScanSeq, TEXT("0"));
  }
  swprintf(currScanSeq, LENGTH(currScanSeq), TEXT("%lu"), g_ScanSequenceNumber);

  lenBuf = ((wcslen(inputString) + 1) > BUFFER_INITIAL_ALLOCATION) ?
           wcslen(inputString) + 1 : BUFFER_INITIAL_ALLOCATION;
  pBuf = calloc(lenBuf, sizeof(WCHAR));
  if (pBuf == NULL) {
    LogMsg(TEXT("substituteUninstallValues: Failure allocating storage for value data, one or more values were not reported."));
    rc = WIPA_GENERAL_FAILURE;
    goto exitSubstituteUninstallValues;
  }
  wcscpy(pBuf, inputString);

  lenBuf2 = lenBuf;
  pBuf2 = calloc(lenBuf2, sizeof(WCHAR));
  if (pBuf2 == NULL) {
    LogMsg(TEXT("substituteUninstallValues: Failure allocating storage for value data, one or more values were not reported."));
    rc = WIPA_GENERAL_FAILURE;
    goto exitSubstituteUninstallValues;
  }

  variPtr = &firstUiItem;
  if ((variPtr->itemName == NULL) ||
      (_wcsicmp(variPtr->itemName, TEXT("KeyName")) != 0)) {
    LogMsg(TEXT("substituteUninstallValues: KeyName value was not first uninstall item."));
    rc = WIPA_GENERAL_FAILURE;
    goto exitSubstituteUninstallValues;
  }
  if (variPtr->itemValue == NULL) {
    LogMsg(TEXT("substituteUninstallValues: KeyName value is not present."));
    rc = WIPA_GENERAL_FAILURE;
    goto exitSubstituteUninstallValues;
  }
  keyName = variPtr->itemValue;
  if (d != Del) {
    if (3 > GetPrivateProfileSection(keyName,
                                     buf3,
                                     LENGTH(buf3),
                                     g_previousIniFile)) {
      d = New;
    } else {
      pIniFileSectionKeyNames = calloc(SECTION_NAMES_BUFFER_SIZE, sizeof(WCHAR));
      if (pIniFileSectionKeyNames == NULL) {
        LogMsg(TEXT("substituteUninstallValues: Could not obtain storage for section key names."));
        rc = WIPA_GENERAL_FAILURE;
        goto exitSubstituteUninstallValues;
      }
      GetPrivateProfileString(keyName,
                              NULL,
                              NULL,
                              pIniFileSectionKeyNames,
                              SECTION_NAMES_BUFFER_SIZE,
                              g_previousIniFile);
    }
  }
  tokenLength = wcslen(vtName);
  memset(pBuf2, 0, lenBuf2 * sizeof(WCHAR));
  /* tempPtr always points to the first character in pBuf that has not yet been copied to pBuf2 */
  tempPtr = pBuf;
  while ((variPtr != NULL) && ((varStrStart = wcsstr(tempPtr, vtName)) != NULL)) {
    if ((variPtr->itemName != NULL) && (variPtr->itemValue != NULL)) {
      firstMatch = TRUE;
      while (varStrStart != NULL) {
        if (!copyWithRealloc(&pBuf2,
                             &lenBuf2,
                             wcslen(pBuf2),
                             tempPtr,
                             varStrStart - tempPtr)) {
          LogMsg(TEXT("substituteUninstallValues: Failure allocating storage for value data, one or more values were not reported."));
          rc = WIPA_GENERAL_FAILURE;
          goto exitSubstituteUninstallValues;
        }
        /* tempPtr always points to the first character in pBuf that has not yet been copied to pBuf2 */
        tempPtr = varStrStart;
        varStrEnd = wcschr(varStrStart + tokenLength, TEXT('%'));
        if (varStrEnd != NULL) {
          if ((varStrEnd - varStrStart - tokenLength > 0) &&
              (wcslen(variPtr->itemName) == (varStrEnd - varStrStart - tokenLength)) &&
              (_wcsnicmp(variPtr->itemName, varStrStart + tokenLength, varStrEnd - varStrStart - tokenLength) == 0)) {
            if (!copyWithRealloc(&pBuf2,
                                 &lenBuf2,
                                 wcslen(pBuf2),
                                 variPtr->itemValue,
                                 wcslen(variPtr->itemValue))) {
              LogMsg(TEXT("substituteUninstallValues: Failure allocating storage for value data, one or more values were not reported."));
              rc = WIPA_GENERAL_FAILURE;
              goto exitSubstituteUninstallValues;
            }
            if (firstMatch) {
              firstMatch = FALSE;
              if (_wcsicmp(variPtr->itemName, TEXT("KeyName")) == 0) {
                foundKeyName = TRUE;
              }
              if (d != Del) {
                removeSectionNameOrKey(pIniFileSectionKeyNames, variPtr->itemName);
                if ((d != New) && (d != Mod)) {
                  if (0 == GetPrivateProfileString(keyName,
                                                   variPtr->itemName,
                                                   TEXT(""),
                                                   buf3,
                                                   LENGTH(buf3),
                                                   g_previousIniFile)) {
                    LogMsg(TEXT("substituteUninstallValues: Setting Mod due to missing key \"%s\" in section \"%s\"."), variPtr->itemName, keyName);
                    d = Mod;
                  } else {
                    if (wcscmp(variPtr->itemValue, buf3) != 0) {
                      LogMsg(TEXT("substituteUninstallValues: Setting Mod due to different values for key \"%s\" in section \"%s\", old = \"%s\", new = \"%s\"."), variPtr->itemName, keyName, buf3, variPtr->itemValue);
                      d = Mod;
                    }
                  }
                }
                WritePrivateProfileString(keyName,
                                          variPtr->itemName,
                                          variPtr->itemValue,
                                          g_currentIniFile);
              }
            }
            /* Start the next search at the character after the closing % of the variable just substituted */
            /* tempPtr always points to the first character in pBuf that has not yet been copied to pBuf2 */
            tempPtr = varStrEnd + 1;
          } else {
            if (!copyWithRealloc(&pBuf2,
                                 &lenBuf2,
                                 wcslen(pBuf2),
                                 varStrStart,
                                 varStrEnd - varStrStart)) {
              LogMsg(TEXT("substituteUninstallValues: Failure allocating storage for value data, one or more values were not reported."));
              rc = WIPA_GENERAL_FAILURE;
              goto exitSubstituteUninstallValues;
            }
            /* Start the next search at the % we just found, since we did not make a substitution */
            /* tempPtr always points to the first character in pBuf that has not yet been copied to pBuf2 */
            tempPtr = varStrEnd;
          }
          varStrStart = wcsstr(tempPtr, vtName);
        } else {
          varStrStart = NULL;
        }
      }
      /* Copy the remainder of the template buffer to the output buffer */
      if (!copyWithRealloc(&pBuf2,
                           &lenBuf2,
                           wcslen(pBuf2),
                           tempPtr,
                           wcslen(tempPtr) + 1)) {
        LogMsg(TEXT("substituteUninstallValues: Failure allocating storage for value data, one or more values were not reported."));
        rc = WIPA_GENERAL_FAILURE;
        goto exitSubstituteUninstallValues;
      }
      /* Copy the output buffer back to the template buffer to be used for the next iteration */
      if (!copyWithRealloc(&pBuf,
                           &lenBuf,
                           0,
                           pBuf2,
                           wcslen(pBuf2) + 1)) {
        LogMsg(TEXT("substituteUninstallValues: Failure allocating storage for value data, one or more values were not reported."));
        rc = WIPA_GENERAL_FAILURE;
        goto exitSubstituteUninstallValues;
      }
      memset(pBuf2, 0, lenBuf2 * sizeof(WCHAR));
      tempPtr = pBuf;
    }
    variPtr = variPtr->pNextItem;
  }
  /* Go through the template one more time to remove any additional %uninstall:variable% occurrences */
  varStrStart = wcsstr(tempPtr, vtName);
  while (varStrStart != NULL) {
    if (!copyWithRealloc(&pBuf2,
                         &lenBuf2,
                         wcslen(pBuf2),
                         tempPtr,
                         varStrStart - tempPtr)) {
      LogMsg(TEXT("substituteUninstallValues: Failure allocating storage for value data, one or more values were not reported."));
      rc = WIPA_GENERAL_FAILURE;
      goto exitSubstituteUninstallValues;
    }
    /* tempPtr always points to the first character in pBuf that has not yet been copied to pBuf2 */
    tempPtr = varStrStart;
    varStrEnd = wcschr(varStrStart + tokenLength, TEXT('%'));
    if (varStrEnd != NULL) {
      /* We copy nothing here as we are just removing unmatched %uninstall:variable% placeholders.  */
      /* tempPtr always points to the first character in pBuf that has not yet been copied to pBuf2 */
      tempPtr = varStrEnd + 1;
      varStrStart = wcsstr(tempPtr, vtName);
    } else {
      varStrStart = NULL;
    }
  }
  /* Copy the remainder of the template buffer to the output buffer */
  if (!copyWithRealloc(&pBuf2,
                       &lenBuf2,
                       wcslen(pBuf2),
                       tempPtr,
                       wcslen(tempPtr) + 1)) {
    LogMsg(TEXT("substituteUninstallValues: Failure allocating storage for value data, one or more values were not reported."));
    rc = WIPA_GENERAL_FAILURE;
    goto exitSubstituteUninstallValues;
  }
  /* Copy the output buffer back to the template buffer to be used for the next iteration */
  if (!copyWithRealloc(&pBuf,
                       &lenBuf,
                       0,
                       pBuf2,
                       wcslen(pBuf2) + 1)) {
    LogMsg(TEXT("substituteUninstallValues: Failure allocating storage for value data, one or more values were not reported."));
    rc = WIPA_GENERAL_FAILURE;
    goto exitSubstituteUninstallValues;
  }

  if (d == Old) {
    if (pIniFileSectionKeyNames != NULL) {
      for (tempPtr = pIniFileSectionKeyNames; tempPtr[0] != TEXT('\0'); tempPtr += (wcslen(tempPtr) + 1)) {
        if (tempPtr[0] != TEXT(' ')) {
          LogMsg(TEXT("substituteUninstallValues: Setting Mod due to missing key \"%s\" in template."), tempPtr);
          d = Mod;
          break;
        }
      }
    }
  }
  switch (d) {
    case Old:
      wcscpy(updateType, TEXT("nochange"));
      break;

    case New:
      wcscpy(updateType, TEXT("insert"));
      if (g_ScanSequenceNumber != 1) {
        /* If this is not the first scan, update the display URL with this product */
        updateUrl();
      }
      break;

    case Mod:
      wcscpy(updateType, TEXT("update"));
      break;

    case Del:
      wcscpy(updateType, TEXT("delete"));
      break;
  }

  memset(pBuf2, 0, lenBuf2 * sizeof(WCHAR));
  tempPtr = pBuf;
  for (i = 0; i < 3; i++) {
    varStrStart = wcsstr(tempPtr, substitutions[i][0]);
    if (varStrStart != NULL) {
      while (varStrStart != NULL) {
        if (!copyWithRealloc(&pBuf2,
                             &lenBuf2,
                             wcslen(pBuf2),
                             tempPtr,
                             varStrStart - tempPtr)) {
          LogMsg(TEXT("substituteUninstallValues: Failure allocating storage for value data, one or more values were not reported."));
          rc = WIPA_GENERAL_FAILURE;
          goto exitSubstituteUninstallValues;
        }
        /* tempPtr always points to the first character in pBuf that has not yet been copied to pBuf2 */
        tempPtr = varStrStart;
        if (!copyWithRealloc(&pBuf2,
                             &lenBuf2,
                             wcslen(pBuf2),
                             substitutions[i][1],
                             wcslen(substitutions[i][1]) + 1)) {
          LogMsg(TEXT("substituteUninstallValues: Failure allocating storage for value data, one or more values were not reported."));
          rc = WIPA_GENERAL_FAILURE;
          goto exitSubstituteUninstallValues;
        }
        /* tempPtr always points to the first character in pBuf that has not yet been copied to pBuf2 */
        tempPtr = varStrStart + wcslen(substitutions[i][0]);
        varStrStart = wcsstr(tempPtr, substitutions[i][0]);
      }
      /* Copy the remainder of the template buffer to the output buffer */
      if (!copyWithRealloc(&pBuf2,
                           &lenBuf2,
                           wcslen(pBuf2),
                           tempPtr,
                           wcslen(tempPtr) + 1)) {
        LogMsg(TEXT("substituteUninstallValues: Failure allocating storage for value data, one or more values were not reported."));
        rc = WIPA_GENERAL_FAILURE;
        goto exitSubstituteUninstallValues;
      }
      /* Copy the output buffer back to the template buffer to be used for the next iteration */
      if (!copyWithRealloc(&pBuf,
                           &lenBuf,
                           0,
                           pBuf2,
                           wcslen(pBuf2) + 1)) {
        LogMsg(TEXT("substituteUninstallValues: Failure allocating storage for value data, one or more values were not reported."));
        rc = WIPA_GENERAL_FAILURE;
        goto exitSubstituteUninstallValues;
      }
      memset(pBuf2, 0, lenBuf2 * sizeof(WCHAR));
      tempPtr = pBuf;
    }
  }

  if ((d == Del) && !foundKeyName) {
    /* We won't create a delete record that does not include the key name */
    rc = WIPA_GENERAL_FAILURE;
  } else {
    *pOutputString = calloc(wcslen(pBuf) + 1, sizeof(WCHAR));
    if (*pOutputString != NULL) {
      wcscpy(*pOutputString, pBuf);
    } else {
      LogMsg(TEXT("substituteUninstallValues: Failure allocating storage for value data, one or more values were not reported."));
      rc = WIPA_GENERAL_FAILURE;
    }
  }
exitSubstituteUninstallValues:
  if ((rc != 0) && (keyName != NULL) && (d != Del)) {
    /* If there was an error, remove the section for this key from the current ini file */
    WritePrivateProfileString(keyName, NULL, NULL, g_currentIniFile);
  }
  if (pIniFileSectionKeyNames != NULL) {
    free(pIniFileSectionKeyNames);
  }
  free(pBuf);
  free(pBuf2);
  if ((rc == 0) && (d == Old)) {
    rc = WIPA_RECORD_NOCHANGE;
  }
  return rc;
}

BOOL copyWithRealloc(WCHAR **pBuffer,
                     DWORD *pLenBuffer,
                     DWORD targetOffset,
                     WCHAR *source,
                     DWORD lenSource)
{
  DWORD endOffset;
  WCHAR *newBuffer;

  endOffset = targetOffset + lenSource;
  if (endOffset + 1 > *pLenBuffer) {
    newBuffer = realloc(*pBuffer, (endOffset + 1 + BUFFER_REALLOC_INCREMENT) * sizeof(WCHAR));
    if (newBuffer != NULL) {
      *pBuffer = newBuffer;
      *pLenBuffer = endOffset + 1 + BUFFER_REALLOC_INCREMENT;
    } else {
      return FALSE;
    }
  }
  wcsncpy(*pBuffer + targetOffset, source, lenSource);
  (*pBuffer)[endOffset] = TEXT('\0');
  return TRUE;
}

/****************************************************************************/
/* LogMsg        : based on the ISSI API function, logs a message to the    */
/*                 file whose path and name are in the global variable      */
/*                 g_logfile.                                               */
/*                                                                          */
/* Inputs        : fmt, a format character string as for printf.            */
/*               : zero or more variable names whose values are to be       */
/*                 substituted in the fmt string.                           */
/*                                                                          */
/* Outputs       : the message is written to the specified file.            */
/*               : the log file is never written as a unicode file.         */  
/****************************************************************************/
/* Logmsg -----------------------------------------------------------------*/
void LogMsg(TCHAR *fmt, ...)            /* write incoming msg to log file   */
{
  /* local vars */
  TCHAR   msgBuf[16384];
  char    dateBuf[81];
  char    outBuf[16384];
  va_list argp;
  time_t  currentTime;
  FILE    *log_fp;

  if (g_logfile[0] == TEXT('\0')) return;

  currentTime = time(NULL);
  strftime(dateBuf, sizeof dateBuf, "%Y%m%d %H%M%S", localtime(&currentTime));

  va_start(argp, fmt);
  _vstprintf(msgBuf, fmt, argp);      /* build msgBuf from info passed    */
#ifdef UNICODE
  WideCharToMultiByte(CP_ACP, 0, msgBuf, -1, outBuf, sizeof outBuf, NULL, NULL);
#else
  strcpy(outBuf, msgBuf);
#endif
  va_end(argp);

  if (g_hLogMsgMutex != NULL) {
    WaitForSingleObject(g_hLogMsgMutex, INFINITE);
  }
  log_fp = _tfopen(g_logfile, TEXT("a"));        /* open the log file append mode    */
  if (log_fp != NULL) {
    fprintf(log_fp, "%s  %s\n", dateBuf, outBuf);  /* write the msg portion            */
    fclose(log_fp); 
  }
  if (g_hLogMsgMutex != NULL) {
    ReleaseMutex(g_hLogMsgMutex);
  }

  return;
}

/* fileExists -------------------------------------------------------------*/
/*
 *  Determine whether a file or directory exists.
 *  Returns:
 *     0 if the entity does not exist
 *     1 if the entity does exist
 *     type contains 'd' or 'f', for directory or file
 */
int fileExists (TCHAR *fn, int *type)
{
  struct _stat st;
  int          rc = 0, exists = 0;

  rc = _tstat(fn, &st);

  if (rc == 0) {
    exists = 1;
    if ((st.st_mode & S_IFMT) == S_IFDIR) {
      *type = _T('d');
    } else {
      *type = _T('f');
    }
  } else {
    exists = 0;
    *type = 0;
  }

  return exists;
}

/****************************************************************************/
/* eraseFileWithErrorLogging : Erase a file after turning off any read only */
/*                 flag, and log an error if one occurs.                    */
/* Inputs        : Path of file to erase                                    */
/* Outputs       : 0 if file was erased, non zero otherwise                 */
/****************************************************************************/
int eraseFileWithErrorLogging(TCHAR *fileToErase)
{
  int rc = 0;

  turnOffAttributes(fileToErase);
  rc = _tremove(fileToErase);
  if (rc != 0) {
    LogMsg(TEXT("eraseFileWithErrorLogging: Unable to delete file \"%s\"."), fileToErase);
  }
  return rc;
}

/****************************************************************************/
/* clearItemQueueNamesAndValues : Clear the variable names and values from  */
/*                                an item queue.                            */
/*                                                                          */
/* Inputs        : none                                                     */
/*                                                                          */
/* Outputs       : the names and values in an item queue are cleared.       */
/****************************************************************************/
void clearItemQueueNamesAndValues(struct variableItem *variPtrFirst)
{
  struct variableItem *variPtr;
  struct variableItem *variPtrNext;

  variPtr = variPtrFirst;
  while (variPtr != NULL) {
    if (variPtr->itemName != NULL) {
      free(variPtr->itemName);
      variPtr->itemName = NULL;
    }
    if (variPtr->itemValue != NULL) {
      free(variPtr->itemValue);
      variPtr->itemValue = NULL;
    }
    variPtr->getItemValue = NULL;
    variPtr->displayName = 0;
    variPtrNext = variPtr->pNextItem;
    variPtr->pNextItem = NULL;
    if (variPtr != variPtrFirst) {
      free(variPtr);
    }
    variPtr = variPtrNext;
  }
}

/****************************************************************************/
/* insertItemQueueNameAndValue : Create an item queue entry, inserting the  */
/*                 item name, item value, item value function pointer, and/ */
/*                 or item message ID number as requested by the caller,    */
/*                 and optionally allocating the entry itself as requested  */
/*                 by the caller.                                           */
/* Inputs        : the current item queue pointer.                          */
/*                 flag indicating to use the current item queue pointer or */
/*                   to allocate a new one and chain it after the current   */
/*                   one.                                                   */
/*                 pointer to the item name for the new entry, or an empty  */
/*                   string or NULL if using the current entry and the item */
/*                   name is already present.                               */
/*                 pointer to the item value for the new entry, or an empty */
/*                   string or NULL if an item value is already present or  */
/*                   an item value is not to be setup.                      */
/*                 length of the item value to ba allocated or 0.  The      */
/*                   caller can use this argument to force storage to be    */
/*                   allocated for an item value, even when no item value   */
/*                   is specified.  This function will allocate enough      */
/*                   storage to hold the actual item value if it is longer  */
/*                   than the length specified by this argument.            */
/*                 pointer to a function to be called to return the item    */
/*                   value at a later time, or NULL if the item value is    */
/*                   specified or is to be added later by another call to   */
/*                   this function.                                         */
/*                 the message ID to be used with FormatMessage() to format */
/*                   the human readable descriptive text for this item      */
/*                   queue entry, or 0 if the data in the entry is not to   */
/*                   be displayed to the user.                              */
/* Outputs       : return code, 0 (success), or WIPA_GENERAL_FAILURE        */
/****************************************************************************/
int insertItemQueueNameAndValue(struct variableItem     *variPtrIn,
                                enum variableItemOption opt,
                                WCHAR                   *newItemName,
                                WCHAR                   *newItemValue,
                                size_t                  forceValueLength,
                                int                     (*newGetItemValue)(WCHAR **),
                                int                     displayStringId)
{
  struct variableItem *variPtr = NULL;
  size_t              valueLength = 0;
  DWORD               i;

  if (opt == INSERT_AFTER_CURRENT) {
    variPtr = (struct variableItem*)calloc(1, sizeof(struct variableItem));
    if (variPtr == NULL) {
      LogMsg(TEXT("insertItemQueueNameAndValue: Failure allocating storage for variableItem."));
      return WIPA_GENERAL_FAILURE;
    }
    variPtr->pNextItem = variPtrIn->pNextItem;
    variPtrIn->pNextItem = variPtr;
  } else { /* opt == USE_CURRENT */
    variPtr = variPtrIn;
  }
  if (newItemName && (newItemName[0] != TEXT('\0'))) {
    if (variPtr->itemName) {
      LogMsg(TEXT("insertItemQueueNameAndValue: New item name specified (\"%s\") but item already has name (\"%s\")."),
             newItemName,
             variPtr->itemName);
      return WIPA_GENERAL_FAILURE;
    }
    variPtr->itemName = (WCHAR *)calloc(wcslen(newItemName) + 1, sizeof(WCHAR));
    if (variPtr->itemName == NULL) {
      LogMsg(TEXT("insertItemQueueNameAndValue: Failure allocating storage for itemName."));
      return WIPA_GENERAL_FAILURE;
    }
    wcscpy(variPtr->itemName, newItemName);
  } else if (!(variPtr->itemName)){
    LogMsg(TEXT("insertItemQueueNameAndValue: No new item name specified and item has no name."));
    return WIPA_GENERAL_FAILURE;
  }
  if (forceValueLength || (newItemValue && (newItemValue[0] != TEXT('\0')))) {
    if (variPtr->itemValue) {
      LogMsg(TEXT("insertItemQueueNameAndValue: New item value specified (\"%s\") but item already has value (\"%s\")."),
             newItemValue,
             variPtr->itemValue);
      return WIPA_GENERAL_FAILURE;
    }
    if (newItemValue) {
      valueLength = wcslen(newItemValue) + 1;
    }
    if (forceValueLength > valueLength) {
      valueLength = forceValueLength;
    }
    variPtr->itemValue = (WCHAR *)calloc(valueLength, sizeof(WCHAR));
    if (variPtr->itemValue == NULL) {
      LogMsg(TEXT("insertItemQueueNameAndValue: Failure allocating storage for itemValue."));
      return WIPA_GENERAL_FAILURE;
    }
    if (newItemValue) {
//    wcscpy(variPtr->itemValue, newItemValue);
      /* Don't allow CR or LF characters in any substitution value. */
      for (i = 0; i < valueLength; i++) {
        if (newItemValue[i] == TEXT('\r')) {
          (variPtr->itemValue)[i] = TEXT('^');
        } else if (newItemValue[i] == TEXT('\n')) {
          (variPtr->itemValue)[i] = TEXT('~');
        } else {
          (variPtr->itemValue)[i] = newItemValue[i];
        }
      }
    }
  }
  if (newGetItemValue) {
    variPtr->getItemValue = newGetItemValue;
  }
  if (displayStringId) {
    variPtr->displayName = displayStringId;
  }
  return 0;
}

int writeOutputString(WCHAR *wszOutput, FILE *fp, UINT uiFileCodePage)
{
  int   rc = 0;
  DWORD dwOutputLength;
  DWORD i;
  int   j;
  char  szmbOutput[8];
  int   mbBytes;

  dwOutputLength = wcslen(wszOutput);
  for (i = 0; i < dwOutputLength; i++) {
    mbBytes = WideCharToMultiByte(uiFileCodePage,
                                  0,
                                  wszOutput + i,
                                  1,
                                  szmbOutput,
                                  sizeof szmbOutput,
                                  NULL,
                                  NULL);
    if (mbBytes == 0) {
      if (ERROR_NO_UNICODE_TRANSLATION == GetLastError()) {
        mbBytes = 1;
        szmbOutput[0] = '?';
      } else {
        LogMsg(TEXT("writeOutPutString: Error converting output string to code page %d"), uiFileCodePage);
        rc = WIPA_GENERAL_FAILURE;
        break;
      }
    }
    for (j = 0; j < mbBytes; j++) {
      fputc(szmbOutput[j], fp);
    }
  }
  return rc;
}

BOOL isZeroLengthFile(WCHAR *filePath)
{
  HANDLE          hFile;
  WIN32_FIND_DATA findData;
  BOOL            zlf = FALSE;

  hFile = FindFirstFile(filePath, &findData);
  if (hFile != INVALID_HANDLE_VALUE) {
    if (((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) &&
        (findData.nFileSizeLow == 0) && (findData.nFileSizeHigh == 0)) {
      zlf = TRUE;
    }
    FindClose(hFile);
  }
  return zlf;
}

/****************************************************************************/
/* renameFileWithErrorLogging : Rename a file and log any error that occurs.*/
/* Inputs        : Old file path, new file path                             */
/* Outputs       : 0 if file was renamed, non zero otherwise                */
/****************************************************************************/
int renameFileWithErrorLogging(WCHAR *oldFilePath, WCHAR *newFilePath)
{
  int rc = 0;

  rc = _wrename(oldFilePath, newFilePath);
  if (rc != 0) {
    LogMsg(TEXT("renameFileWithErrorLogging: Unable to rename file \"%s\" to \"%s\"."), oldFilePath, newFilePath);
  }
  return rc;
}

/*
 *  If the file path/name passed in exists, turn off the read only, hidden,
 *  and system attributes.
 */
void turnOffAttributes(WCHAR *fn)
{
  int   ft;
  WCHAR buf[_MAX_PATH + 1];

  if (fileExists(fn, &ft) && ft == 'f') {              /* The file exists */
    if (!SetFileAttributes(fn, FILE_ATTRIBUTE_NORMAL)) {
      swprintf(buf, LENGTH(buf), TEXT("attrib -r -h -s %s"), fn);
      executeCmdHidden(buf);
    }
  }
}

int httpGetFile(TCHAR *server,
                TCHAR *sourceFile,
                TCHAR *localFile,
                BOOL  secure)
{
  int           rc = 0;
  HINTERNET     hSession = NULL;
  HINTERNET     hConnect = NULL;
  HINTERNET     hOpenRequest = NULL;
  TCHAR         statusBuf[32];
  char          *buf = NULL;
  BOOL          result;
  DWORD         dwRc;
  DWORD         lenRead;
  DWORD         bytesRead = 0;
  TCHAR         msg[1024];
  DWORD         len;
  LPCTSTR       acceptTypes[2] = {TEXT("*/*"), NULL};
  HANDLE        fp = INVALID_HANDLE_VALUE;
  DWORD         bytesWritten;
  int           retryCount;
  INTERNET_PORT serverPort;
  DWORD         internetOpenFlags = INTERNET_FLAG_NO_CACHE_WRITE |
                                    INTERNET_FLAG_RELOAD |
                                    INTERNET_FLAG_NO_COOKIES |
                                    INTERNET_FLAG_NO_UI;

  buf = malloc(BLOCK_SIZE);
  if (buf == NULL) {
    LogMsg(TEXT("httpGetFile: Could not obtain storage for transfer of \"%s\"."), localFile);
    rc = WIPA_GENERAL_FAILURE;
    goto endProc;
  }

  if (secure) {
    serverPort = INTERNET_DEFAULT_HTTPS_PORT;
    internetOpenFlags |= INTERNET_FLAG_SECURE;
  } else {
    serverPort = INTERNET_DEFAULT_HTTP_PORT;
  }

  LogMsg(TEXT("httpGetFile: Copy - Source: %s  Target: %s"), sourceFile, localFile);
  hSession = InternetOpen(TEXT("IBM Installed Software Monitor"),
                          INTERNET_OPEN_TYPE_PRECONFIG,
                          NULL,
                          NULL,
                          0);
  if (hSession == NULL) {
    dwRc = formatWindowsErrorMsg(msg);
    LogMsg(TEXT("httpGetFile: InternetOpen failed, rc = %lu, %s"), dwRc, msg);
    rc = WIPA_GENERAL_FAILURE;
    goto endProc;
  }
  
  for (retryCount = 0;
       (hConnect == NULL) && (retryCount < 2);
       retryCount++) {
    if (retryCount) {
      /* If this is a connect retry, wait 3 seconds. */
      Sleep(3000);
    }
    hConnect = InternetConnect(hSession,
                               server,
                               serverPort,
                               NULL,
                               NULL,
                               INTERNET_SERVICE_HTTP,
                               0,
                               0);
  }
  if (hConnect == NULL) {
    dwRc = formatWindowsErrorMsg(msg);
    LogMsg(TEXT("httpGetFile: InternetConnect failed, rc = %lu, %s"), dwRc, msg);
    rc = WIPA_GENERAL_FAILURE;
    goto endProc;
  }

  for (retryCount = 0;
       (hOpenRequest == NULL) && (retryCount < 2);
       retryCount++) {
    if (retryCount) {
      /* If this is an open request retry, wait 3 seconds. */
      Sleep(3000);
    }
    hOpenRequest = HttpOpenRequest(hConnect,
                                   NULL,
                                   sourceFile,
                                   NULL,
                                   NULL,
                                   acceptTypes,
                                   internetOpenFlags,
                                   0);
  }
  if (hOpenRequest == NULL) {
    dwRc = formatWindowsErrorMsg(msg);
    LogMsg(TEXT("httpGetFile: HttpOpenRequest failed, rc = %lu, %s"), dwRc, msg);
    rc = WIPA_GENERAL_FAILURE;
    goto endProc;
  }

  result = HttpSendRequest(hOpenRequest, NULL, 0, NULL, 0);
  if (!result) {
    dwRc = formatWindowsErrorMsg(msg);
    LogMsg(TEXT("httpGetFile: HttpSendRequest failed, rc = %lu, %s"), dwRc, msg);
    rc = WIPA_GENERAL_FAILURE;
    goto endProc;
  }

  len = sizeof statusBuf;
  memset(statusBuf, 0, sizeof statusBuf);
  result = HttpQueryInfo(hOpenRequest, HTTP_QUERY_STATUS_CODE, (LPVOID)statusBuf, &len, 0);
  if (!result) {
    dwRc = formatWindowsErrorMsg(msg);
    LogMsg(TEXT("httpGetFile: HttpQueryInfo failed, rc = %lu, %s"), dwRc, msg);
    rc = WIPA_GENERAL_FAILURE;
    goto endProc;
  }
  if (_tcscmp(statusBuf, TEXT("200")) != 0) {
    LogMsg(TEXT("httpGetFile: HttpQueryInfo status code: %s"), statusBuf);
    rc = WIPA_GENERAL_FAILURE;
    goto endProc;
  }

  fp = CreateFile(localFile,
                  GENERIC_READ | GENERIC_WRITE,
                  0,
                  NULL,
                  CREATE_ALWAYS,
                  FILE_ATTRIBUTE_NORMAL,
                  NULL);
  if (fp == INVALID_HANDLE_VALUE) {
    LogMsg(TEXT("httpGetFile: Open failed for file \"%s\"."), localFile);
    rc = WIPA_GENERAL_FAILURE;
    goto endProc;
  }
  len = sizeof buf;
  memset(buf, 0, BLOCK_SIZE);
  result = TRUE;
  while (result) {
    result = InternetReadFile(hOpenRequest, (LPVOID)buf, len, &lenRead);
    if (result) {
      if (lenRead == 0) {
        break;
      } else {
        bytesRead += lenRead;
        if ((!WriteFile(fp, buf, lenRead, &bytesWritten, NULL)) ||
            (lenRead != bytesWritten)) {
          LogMsg(TEXT("httpGetFile: Error writing file \"%s\"."), localFile);
          rc = WIPA_GENERAL_FAILURE;
          goto endProc;
        }
      }
    }
  }
  if (result) {
    if (bytesRead == 0) {
      LogMsg(TEXT("httpGetFile: Empty file received from InternetReadFile."));
      rc = WIPA_GENERAL_FAILURE;
      goto endProc;
    }
  } else {
    dwRc = formatWindowsErrorMsg(msg);
    LogMsg(TEXT("httpGetFile: InternetReadFile failed, rc = %lu, %s"), dwRc, msg);
    rc = WIPA_GENERAL_FAILURE;
    goto endProc;
  }

endProc:
  if (hOpenRequest != NULL) {
    InternetCloseHandle(hOpenRequest);
  }
  if (hConnect != NULL) {
    InternetCloseHandle(hConnect);
  }
  if (hSession != NULL) {
    InternetCloseHandle(hSession);
  }
  if (buf) {
    free(buf);
  }
  if (fp != INVALID_HANDLE_VALUE) {
    CloseHandle(fp);
  }
  return rc;
}

/*****************************************************************************/
/* formatWindowsErrorMsg                                                     */
/*****************************************************************************/
DWORD formatWindowsErrorMsg(TCHAR *msg)
{
/*-- Local Variables  -------------------------------------------------------*/
  LPVOID lpMsgBuf = NULL;
  DWORD  rc;
/*-- Code -------------------------------------------------------------------*/
  msg[0] = TEXT('\0');
  rc = GetLastError();
  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL,
                rc,
                MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
                (LPTSTR)&lpMsgBuf,
                0,
                NULL);
  if (lpMsgBuf != NULL) {
    _tcscpy(msg, lpMsgBuf);
    LocalFree(lpMsgBuf);
  } else {
    msg[0] = TEXT('\0');
  }
  return rc;
}

void updateUrl(void)
{
  WCHAR tempDisplayUrl[2000] = TEXT("");
  WCHAR tempDisplayUrl2[2000] = TEXT("");
  int   lengthUrl;
  int   rcswprintf;
  int   maxChars;
  WCHAR prefixString[2];
  WCHAR displayName[2048] = TEXT("");
  WCHAR displayVersion[2048] = TEXT("");
  WCHAR publisher[2048] = TEXT("");
  DWORD urlLength;
  PVI   variPtr;


  variPtr = &firstUiItem;
  while (variPtr != NULL) {
    if ((variPtr->itemName != NULL) && (variPtr->itemValue != NULL)) {
      if (_wcsicmp(variPtr->itemName, TEXT("DisplayName")) == 0) {
        wcscpy(displayName, variPtr->itemValue);
      }
      else if (_wcsicmp(variPtr->itemName, TEXT("DisplayVersion")) == 0) {
        wcscpy(displayVersion, variPtr->itemValue);
      }
      else if (_wcsicmp(variPtr->itemName, TEXT("Publisher")) == 0) {
        wcscpy(publisher, variPtr->itemValue);
      }
    }
    variPtr = variPtr->pNextItem;
  }
  if (productShouldBeDisplayed(publisher, displayName)) {
    wcscpy(tempDisplayUrl, g_displayUrl);
    g_productNumber++;
    if (g_productNumber != 1) {
      wcscpy(prefixString, TEXT("&"));
    } else {
      prefixString[0] = TEXT('\0');
    }
    lengthUrl = wcslen(tempDisplayUrl);
    maxChars = LENGTH(tempDisplayUrl) - lengthUrl;
    rcswprintf = swprintf(tempDisplayUrl + lengthUrl,
                          maxChars,
                          TEXT("%sname%d=%s"),
                          prefixString,
                          g_productNumber,
                          displayName);
    if ((rcswprintf != (maxChars - 1)) && (rcswprintf != -1)) {
      lengthUrl = wcslen(tempDisplayUrl);
      maxChars = LENGTH(tempDisplayUrl) - lengthUrl;
      if (publisher[0] != TEXT('\0')) {
        rcswprintf = swprintf(tempDisplayUrl + lengthUrl,
                              maxChars,
                              TEXT("&mfg%d=%s"),
                              g_productNumber,
                              publisher);
      } else {
        rcswprintf = 0;
      }
      if ((rcswprintf != (maxChars - 1)) && (rcswprintf != -1)) {
        lengthUrl = wcslen(tempDisplayUrl);
        maxChars = LENGTH(tempDisplayUrl) - lengthUrl;
        if (displayVersion[0] != TEXT('\0')) {
          rcswprintf = swprintf(tempDisplayUrl + lengthUrl,
                                maxChars,
                                TEXT("&ver%d=%s"),
                                g_productNumber,
                                displayVersion);
        } else {
          rcswprintf = 0;
        }
        if ((rcswprintf != (maxChars - 1)) && (rcswprintf != -1)) {
          urlLength = LENGTH(tempDisplayUrl2);
          if (InternetCanonicalizeUrl(tempDisplayUrl,
                                      tempDisplayUrl2,
                                      &urlLength,
                                      0)) {
            /* We verify that the URL can be encoded, but we don't save the */
            /* encoded value at this point.                                 */

            /* Copy the updated URL back */ 
            wcscpy(g_displayUrl, tempDisplayUrl);
          } else {
            LogMsg(TEXT("updateUrl: The URL \"%s\" could not be encoded, the product \"%s\" will not be shown."), tempDisplayUrl, displayName);
          }
        } else {
          LogMsg(TEXT("updateUrl: DisplayVersion \"%s\" for product \"%s\" caused a URL length overflow, the product will not be shown."), displayVersion, displayName);
          g_productNumber--;
        }
      } else {
        LogMsg(TEXT("updateUrl: Publisher \"%s\" for product \"%s\" caused a URL length overflow, the product will not be shown."), publisher, displayName);
        g_productNumber--;
      }
    } else {
      LogMsg(TEXT("updateUrl: DisplayName \"%s\" caused a URL length overflow, the product will not be shown."), displayName);
      g_productNumber--;
    }
  } else {
    LogMsg(TEXT("updateUrl: DisplayName \"%s\" was excluded from the end user display."), displayName);
  }
}

int verifyCrc(LPCWSTR filePath, LPCWSTR fileCrc)
{
  FILE          *fp;
  int           ch;
  cm_t          cmt;
  p_cm_t        pcmt = &cmt;
  unsigned long crc;
  int           rc = 0;
  WCHAR         wszCrc[32];

  fp = _wfopen(filePath, TEXT("rb"));
  if (fp == NULL) {
    LogMsg(TEXT("verifyCrc: The file \"%s\" could not be opened for read."), filePath);
    rc = CRC_FILE_OPEN_ERROR;
  } else {
    pcmt->cm_width = 32;     
    pcmt->cm_poly  = 0x04C11DB7L;
    pcmt->cm_init  = 0xFFFFFFFFL;     
    pcmt->cm_refin = TRUE;   
    pcmt->cm_refot = TRUE;   
    pcmt->cm_xorot = 0xFFFFFFFFL;     
    cm_ini(pcmt);
    ch = fgetc(fp);
    while (ch != EOF) {
      cm_nxt(pcmt, ch);
      ch = fgetc(fp);
    }
    if (ferror(fp)) {
      LogMsg(TEXT("verifyCrc: A file read error occurred while processing \"%s\"."), filePath);
      rc = CRC_FILE_READ_ERROR;
    } else {
      crc = cm_crc(pcmt);
      swprintf(wszCrc, LENGTH(wszCrc), TEXT("%08lX"), crc);
      if (_wcsicmp(fileCrc, wszCrc) == 0) {
        rc = CRC_EQUAL;
      } else {
        rc = CRC_NOT_EQUAL;
      }
    }
    fclose(fp);
  }
  return rc;
}

void initializeGlobals(LPCWSTR wipaIni, LPCWSTR countryCode)
{
  WCHAR wszFilesToPreserve[8];
  WCHAR buf[2048];

  
  swprintf(buf, LENGTH(buf), TEXT("CountryCode_%s"),countryCode);

  if (0 != GetPrivateProfileString(TEXT("Parameters"),
                                   TEXT("FilesToPreserve"),
                                   TEXT(""),
                                   wszFilesToPreserve,
                                   LENGTH(wszFilesToPreserve),
                                   wipaIni)) {
    g_FilesToPreserve = _wtoi(wszFilesToPreserve);
    if ((g_FilesToPreserve < 1) || (g_FilesToPreserve > 1000)) {
      g_FilesToPreserve = DEFAULT_FILES_TO_PRESERVE;
      LogMsg(TEXT("initializeGlobals: The FilesToPreserve value from \"%s\" was invalid."), wipaIni);
    }
  }

  // DisplayUrl - Try to get the geo specific value first if not found then use the default
  g_displayUrl[0] = TEXT('\0');
  if (GetPrivateProfileString(buf, TEXT("DisplayUrl"), TEXT(""), g_displayUrl, LENGTH(g_displayUrl), wipaIni) > 0) {
    LogMsg(TEXT("Using [%s] DisplayUrl= from wipa.ini"),buf);
  } else {
    if (0 == GetPrivateProfileString(TEXT("Parameters"), TEXT("DisplayUrl"), TEXT(""), g_displayUrl, LENGTH(g_displayUrl), wipaIni)) {
      LogMsg(TEXT("[Parameters] DisplayUrl= from wipa.ini not found, using default value."));
      wcscpy(g_displayUrl, DEFAULT_DISPLAY_URL);
    }
  } 
  
  if (0 == GetPrivateProfileString(TEXT("Parameters"),
                                   TEXT("UIPUBLISHEREXCLUDE"),
                                   TEXT(""),
                                   g_uninPublisherExclude,
                                   LENGTH(g_uninPublisherExclude),
                                   wipaIni)) {
    g_uninPublisherExclude[0] = TEXT('\0');
  }
  if (g_uninPublisherExclude[0] == TEXT('\0')) {
    /* UIPUBLISHERINCLUDE is only allowed if UIPUBLISHEREXCLUDE is not specified */
    if (0 == GetPrivateProfileString(TEXT("Parameters"),
                                     TEXT("UIPUBLISHERINCLUDE"),
                                     TEXT(""),
                                     g_uninPublisherInclude,
                                     LENGTH(g_uninPublisherInclude),
                                     wipaIni)) {
      g_uninPublisherInclude[0] = TEXT('\0');
    }
  }
  if (0 == GetPrivateProfileString(TEXT("Parameters"),
                                   TEXT("UIDISPLAYNAMEEXCLUDE"),
                                   TEXT(""),
                                   g_uninDisplayNameExclude,
                                   LENGTH(g_uninDisplayNameExclude),
                                   wipaIni)) {
    g_uninDisplayNameExclude[0] = TEXT('\0');
  }
  if (g_uninDisplayNameExclude[0] == TEXT('\0')) {
    /* UIDISPLAYNAMEINCLUDE is only allowed if UIDISPLAYNAMEEXCLUDE is not specified */
    if (0 == GetPrivateProfileString(TEXT("Parameters"),
                                     TEXT("UIDISPLAYNAMEINCLUDE"),
                                     TEXT(""),
                                     g_uninDisplayNameInclude,
                                     LENGTH(g_uninDisplayNameInclude),
                                     wipaIni)) {
      g_uninDisplayNameInclude[0] = TEXT('\0');
    }
  }
  if (0 == GetPrivateProfileString(TEXT("Parameters"),
                                   TEXT("USERPUBLISHEREXCLUDE"),
                                   TEXT(""),
                                   g_userPublisherExclude,
                                   LENGTH(g_userPublisherExclude),
                                   wipaIni)) {
    g_userPublisherExclude[0] = TEXT('\0');
  }
  if (g_userPublisherExclude[0] == TEXT('\0')) {
    /* USERPUBLISHERINCLUDE is only allowed if USERPUBLISHEREXCLUDE is not specified */
    if (0 == GetPrivateProfileString(TEXT("Parameters"),
                                     TEXT("USERPUBLISHERINCLUDE"),
                                     TEXT(""),
                                     g_userPublisherInclude,
                                     LENGTH(g_userPublisherInclude),
                                     wipaIni)) {
      g_userPublisherInclude[0] = TEXT('\0');
    }
  }
  if (0 == GetPrivateProfileString(TEXT("Parameters"),
                                   TEXT("USERDISPLAYNAMEEXCLUDE"),
                                   TEXT(""),
                                   g_userDisplayNameExclude,
                                   LENGTH(g_userDisplayNameExclude),
                                   wipaIni)) {
    g_userDisplayNameExclude[0] = TEXT('\0');
  }
  if (g_userDisplayNameExclude[0] == TEXT('\0')) {
    /* USERDISPLAYNAMEINCLUDE is only allowed if USERDISPLAYNAMEEXCLUDE is not specified */
    if (0 == GetPrivateProfileString(TEXT("Parameters"),
                                     TEXT("USERDISPLAYNAMEINCLUDE"),
                                     TEXT(""),
                                     g_userDisplayNameInclude,
                                     LENGTH(g_userDisplayNameInclude),
                                     wipaIni)) {
      g_userDisplayNameInclude[0] = TEXT('\0');
    }
  }
}

void processNoticeText(LPWSTR outText, LPCWSTR inText)
{
  int i;
  int len;

  len = wcslen(inText);
  outText[0] = TEXT('\0');
  for (i = 0; i < len; i++) {
    if ((inText[i] == TEXT('\\')) && (inText[i + 1] == TEXT('n'))) {
      wcscat(outText, TEXT("\r\n"));
      i++;
    } else {
      outText[i] = inText[i];
      outText[i + 1] = TEXT('\0');
    }
  }
}

/****************************************************************************/
/* substituteOneLine: Scan one line for %sourceid:variable% place holders,  */
/*                 substituting the actual values from the variable item    */
/*                 structures.                                              */
/* Inputs        : inputString, the string into which substitutions are to  */
/*               : be made                                                  */
/* Outputs       : outputString, the string with values substituted for     */
/*               : place holders                                            */
/****************************************************************************/
void substituteOneLine(WCHAR **pOutputString, WCHAR *inputString, WCHAR *iniFilePath)
{
  int    i;
  WCHAR  *pBuf = NULL;
  WCHAR  *pBuf2 = NULL;
  DWORD  lenBuf = 0;
  DWORD  lenBuf2 = 0;
  WCHAR  *varStrStart;
  WCHAR  *varStrEnd;
  WCHAR  *tempPtr;
  WCHAR  *valueData = NULL;
  BOOL   freeValueData = FALSE;
  WCHAR  sectionName[32];
  int    tokenLength;
  struct variableItem *variPtr;

  *pOutputString = NULL;
  lenBuf = ((wcslen(inputString) + 1) > BUFFER_INITIAL_ALLOCATION) ?
           wcslen(inputString) + 1 : BUFFER_INITIAL_ALLOCATION;
  pBuf = calloc(lenBuf, sizeof(WCHAR));
  if (pBuf == NULL) {
    LogMsg(TEXT("substituteOneLine: Failure allocating storage for value data, one or more values were not reported."));
    goto ExitSubstituteOneLine;
  }
  lenBuf2 = lenBuf;
  pBuf2 = calloc(lenBuf2, sizeof(WCHAR));
  if (pBuf2 == NULL) {
    LogMsg(TEXT("substituteOneLine: Failure allocating storage for value data, one or more values were not reported."));
    goto ExitSubstituteOneLine;
  }

  wcscpy(pBuf, inputString);
  for (i = 0; i < VARIABLE_TYPES_COUNT; i++) {
    memset(pBuf2, 0, lenBuf2 * sizeof(WCHAR));
    tempPtr = pBuf;
    tokenLength = wcslen(variableTypes[i].vtName);
    varStrStart = wcsstr(tempPtr, variableTypes[i].vtName);
    while (varStrStart != NULL) {
      if (!copyWithRealloc(&pBuf2,
                           &lenBuf2,
                           wcslen(pBuf2),
                           tempPtr,
                           varStrStart - tempPtr)) {
        LogMsg(TEXT("substituteOneLine: Failure allocating storage for value data, one or more values were not reported."));
        goto ExitSubstituteOneLine;
      }
      varStrEnd = wcschr(varStrStart + tokenLength, TEXT('%'));
      if (varStrEnd == NULL) {
        tempPtr = varStrStart;
        varStrStart = NULL;
      } else {
        if (varStrEnd - varStrStart - tokenLength > 0) {
          variPtr = variableTypes[i].pVtFirstItem;
          while (variPtr != NULL) {
            if ((variPtr->itemName != NULL) &&
                (wcslen(variPtr->itemName) == (varStrEnd - varStrStart - tokenLength)) &&
                (_wcsnicmp(variPtr->itemName, varStrStart + tokenLength, varStrEnd - varStrStart - tokenLength) == 0)) {
              if ((variPtr->itemValue != NULL) || (variPtr->getItemValue != NULL)) {
                valueData = NULL;
                freeValueData = FALSE;
                if (variPtr->itemValue != NULL) {
                  valueData = variPtr->itemValue;
                } else if (variPtr->getItemValue != NULL) {
                  variPtr->getItemValue(&valueData);
                  freeValueData = TRUE;
                }
                if (valueData != NULL) {
                  if (iniFilePath && (variPtr->displayName)) {
                    _itow(variPtr->displayName, sectionName, 10);
                    WritePrivateProfileString(sectionName, TEXT("Data"), valueData, iniFilePath);
                  }
                  if (!copyWithRealloc(&pBuf2,
                                       &lenBuf2,
                                       wcslen(pBuf2),
                                       valueData,
                                       wcslen(valueData))) {
                    LogMsg(TEXT("substituteOneLine: Failure allocating storage for value data, one or more values were not reported."));
                    if (freeValueData) {
                      free(valueData);
                    }
                    goto ExitSubstituteOneLine;
                  }
                  if (freeValueData) {
                    free(valueData);
                    valueData = NULL;
                  }
                }
              }
              break;
            }
            variPtr = variPtr->pNextItem;
          }
        }
        tempPtr = varStrEnd + 1;
        varStrStart = wcsstr(tempPtr, variableTypes[i].vtName);
      }
    }
    if (!copyWithRealloc(&pBuf2,
                         &lenBuf2,
                         wcslen(pBuf2),
                         tempPtr,
                         wcslen(tempPtr))) {
      LogMsg(TEXT("substituteOneLine: Failure allocating storage for value data, one or more values were not reported."));
      goto ExitSubstituteOneLine;
    }
    if (!copyWithRealloc(&pBuf,
                         &lenBuf,
                         0,
                         pBuf2,
                         wcslen(pBuf2))) {
      LogMsg(TEXT("substituteOneLine: Failure allocating storage for value data, one or more values were not reported."));
      goto ExitSubstituteOneLine;
    }
  }
  *pOutputString = calloc(wcslen(pBuf2) + 1, sizeof(WCHAR));
  if (*pOutputString != NULL) {
    wcscpy(*pOutputString, pBuf2);
  } else {
    LogMsg(TEXT("substituteOneLine: Failure allocating storage for value data, one or more values were not reported."));
  }
ExitSubstituteOneLine:
  free(pBuf);
  free(pBuf2);
}

/****************************************************************************/
/* initSpNamesAndValues : Initialize the names and values) of all source-id */
/*                 "special" variables.                                     */
/* Inputs        : none                                                     */
/* Outputs       : return code, 0 (success), or WIPA_GENERAL_FAILURE        */
/****************************************************************************/
int initSpNamesAndValues(void)
{
  int   rc = 0;
  VI    *variPtr;
  HKEY  hKey = NULL;
  DWORD dataBufferSize, valueType;
  WCHAR machineID[2048] = TEXT("");
  WCHAR hrGroupId[2048] = TEXT("");
  WCHAR hrUnitId[2048] = TEXT("");
  BOOL  regKeyOpened = FALSE;

  regKeyOpened = (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                                                TEXT("SOFTWARE\\IGS\\C4EBReg"),
                                                0L,
                                                KEY_READ,
                                                &hKey));

  clearItemQueueNamesAndValues(&firstSpItem);

  variPtr = &firstSpItem;
  if (regKeyOpened) {
    dataBufferSize = sizeof machineID; /* set the size of the data buffer */
    if (ERROR_SUCCESS == RegQueryValueEx(hKey,
                                         TEXT("MachineId"),
                                         NULL,
                                         &valueType,
                                         (LPBYTE)machineID,
                                         &dataBufferSize)) {
      swprintf(g_machineID, LENGTH(g_machineID), TEXT("%s"), machineID);
    } else {
      machineID[0] = TEXT('\0');
    }
  } else {
    machineID[0] = TEXT('\0');
  }

  rc = insertItemQueueNameAndValue(variPtr,
                                   USE_CURRENT,
                                   TEXT("MachineID"),
                                   machineID,
                                   0,
                                   NULL,
                                   0);
  if (rc != 0) {
    goto ExitinitSpNamesAndValues;
  }

  if (regKeyOpened) {
    RegCloseKey(hKey);
  }
  regKeyOpened = (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                                                TEXT("SOFTWARE\\IGS\\C4EBReg\\special"),
                                                0L,
                                                KEY_READ,
                                                &hKey));

  if (regKeyOpened) {
    dataBufferSize = sizeof hrGroupId; /* set the size of the data buffer */
    if (ERROR_SUCCESS != RegQueryValueEx(hKey,
                                         TEXT("hrGroupId"),
                                         NULL,
                                         &valueType,
                                         (LPBYTE)hrGroupId,
                                         &dataBufferSize)) {
      hrGroupId[0] = TEXT('\0');
    }
  } else {
    hrGroupId[0] = TEXT('\0');
  }

  rc = insertItemQueueNameAndValue(variPtr,
                                   INSERT_AFTER_CURRENT,
                                   TEXT("hrGroupId"),
                                   hrGroupId,
                                   0,
                                   NULL,
                                   0);
  if (rc == 0) {
    variPtr = variPtr->pNextItem;
  } else {
    goto ExitinitSpNamesAndValues;
  }

  if (regKeyOpened) {
    dataBufferSize = sizeof hrUnitId; /* set the size of the data buffer */
    if (ERROR_SUCCESS != RegQueryValueEx(hKey,
                                         TEXT("hrUnitId"),
                                         NULL,
                                         &valueType,
                                         (LPBYTE)hrUnitId,
                                         &dataBufferSize)) {
      hrUnitId[0] = TEXT('\0');
    }
  } else {
    hrUnitId[0] = TEXT('\0');
  }

  rc = insertItemQueueNameAndValue(variPtr,
                                   INSERT_AFTER_CURRENT,
                                   TEXT("hrUnitId"),
                                   hrUnitId,
                                   0,
                                   NULL,
                                   0);
  if (rc == 0) {
    variPtr = variPtr->pNextItem;
  } else {
    goto ExitinitSpNamesAndValues;
  }
ExitinitSpNamesAndValues:
  if (regKeyOpened) {
    RegCloseKey(hKey);
  }
  return rc;
}

BOOL realtimeStatusCheck(WCHAR *rtUploadServer,
                         WCHAR *rtUploadPort,
                         WCHAR *rtStatusScript,
                         BOOL  rtUploadSecure)
{
  BOOL          myRc = FALSE;
  HINTERNET     hSession = NULL;
  HINTERNET     hConnect = NULL;
  HINTERNET     hOpenRequest = NULL;
  char          szRtUploadServer[512];
  char          szRtStatusScript[128];
  char          buf[1024];
  BOOL          result;
  DWORD         dwRc;
  int           rc;
  DWORD         lenRead;
  DWORD         bytesRead = 0;
  wchar_t       msg[1024];
  DWORD         len;
  INTERNET_PORT serverPort = INTERNET_DEFAULT_HTTP_PORT;
  char          requestHeader[256]; 
  char          *tempPtr;
  DWORD         internetOpenFlags = INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD;
  int           retryCount;

  if ((rtUploadPort != NULL) && (rtUploadPort[0] != TEXT('\0'))) {
    serverPort = _wtoi(rtUploadPort);
  } else if (rtUploadSecure) {
    serverPort = INTERNET_DEFAULT_HTTPS_PORT;
  } else {
    serverPort = INTERNET_DEFAULT_HTTP_PORT;
  }

  hSession = InternetOpenA("HTTP/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
  if (hSession == NULL) {
    dwRc = formatWinErrMsg(msg);
    LogMsg(TEXT("realtimeStatusCheck: InternetOpen failed, rc = %lu, %s"), dwRc, msg);
    goto endProc;
  }
  
  wcstombs(szRtUploadServer, rtUploadServer, sizeof szRtUploadServer);
  for (retryCount = 0;
       (hConnect == NULL) && (retryCount < 2);
       retryCount++) {
    if (retryCount) {
      /* If this is a connect retry, wait 3 seconds. */
      Sleep(3000);
    }
    hConnect = InternetConnectA(hSession,
                                szRtUploadServer,
                                serverPort,
                                NULL,
                                NULL,
                                INTERNET_SERVICE_HTTP,
                                0,
                                0);
  }
  if (hConnect == NULL) {
    dwRc = formatWinErrMsg(msg);
    LogMsg(TEXT("realtimeStatusCheck: InternetConnect failed, rc = %lu, %s"), dwRc, msg);
    goto endProc;
  }

  if (rtUploadSecure) {
    internetOpenFlags |= INTERNET_FLAG_SECURE;
  }
  wcstombs(szRtStatusScript, rtStatusScript, sizeof szRtStatusScript);
  for (retryCount = 0;
       (hOpenRequest == NULL) && (retryCount < 2);
       retryCount++) {
    if (retryCount) {
      /* If this is an open request retry, wait 3 seconds. */
      Sleep(3000);
    }
    hOpenRequest = HttpOpenRequestA(hConnect,
                                    "POST",
                                    szRtStatusScript,
                                    NULL,
                                    NULL,
                                    NULL,
                                    internetOpenFlags,
                                    0);
  }
  if (hOpenRequest == NULL) {
    dwRc = formatWinErrMsg(msg);
    LogMsg(TEXT("realtimeStatusCheck: HttpOpenRequest failed, rc = %lu, %s"), dwRc, msg);
    goto endProc;
  }

  strcpy(requestHeader, "Connection: close\r\n");
  result = HttpAddRequestHeadersA(hOpenRequest,
                                  requestHeader,
                                  strlen(requestHeader),
                                  HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE);
  if (!result) {
    rc = formatWinErrMsg(msg);
    LogMsg(TEXT("realtimeStatusCheck: HttpAddRequestHeaders for Connection failed, rc = %lu, %s"), rc, msg);
    /* If this fails for some reason, we just continue without this header */
  }

  result = HttpSendRequestA(hOpenRequest, NULL, 0, NULL, 0);
  if (!result) {
    dwRc = formatWinErrMsg(msg);
    LogMsg(TEXT("realtimeStatusCheck: HttpSendRequest failed, rc = %lu, %s"), dwRc, msg);
    goto endProc;
  }

  len = sizeof buf;
  memset(buf, 0, sizeof buf);
  result = HttpQueryInfoA(hOpenRequest, HTTP_QUERY_STATUS_CODE, buf, &len, 0);
  if (!result) {
    dwRc = formatWinErrMsg(msg);
    LogMsg(TEXT("realtimeStatusCheck: HttpQueryInfo failed, rc = %lu, %s"), dwRc, msg);
    goto endProc;
  }
  if (strcmp(buf, "200") != 0) {
    LogMsg(TEXT("realtimeStatusCheck: HttpQueryInfo status code: %hs"), buf);
    goto endProc;
  }

  len = sizeof buf;
  memset(buf, 0, sizeof buf);
  result = TRUE;
  while (result) {
    result = InternetReadFile(hOpenRequest, (LPVOID)(buf + bytesRead), len - bytesRead, &lenRead);
    if (result) {
      if (lenRead == 0) {
        break;
      } else {
        bytesRead += lenRead;
      }
    }
  }
  if (result) {
    /* InternetReadFile can put extraneous garbage in the buffer past the end of the data read */
    buf[bytesRead] = '\0';
    if (bytesRead == 0) {
      LogMsg(TEXT("realtimeStatusCheck: Empty results file received from InternetReadFile."));
      goto endProc;
    }
    tempPtr = strtok(buf, " \r\n\t");
    if (tempPtr != NULL) {
      rc = atoi(tempPtr);
      if (rc == 0) {
        myRc = TRUE;
      } else {
        LogMsg(TEXT("realtimeStatusCheck: Real time status script returned %hs."), tempPtr);
        goto endProc;
      }
    } else {
      LogMsg(TEXT("realtimeStatusCheck: Real time status script returned bad result string."));
      goto endProc;
    }
  } else {
    dwRc = formatWinErrMsg(msg);
    LogMsg(TEXT("realtimeStatusCheck: InternetReadFile failed, rc = %lu, %s"), dwRc, msg);
    goto endProc;
  }

endProc:
  if (hOpenRequest != NULL) {
    InternetCloseHandle(hOpenRequest);
  }
  if (hConnect != NULL) {
    InternetCloseHandle(hConnect);
  }
  if (hSession != NULL) {
    InternetCloseHandle(hSession);
  }
  if (!myRc) {
    LogMsg(TEXT("realtimeStatusCheck: Real time status script did not allow real time uploads."));
  }
  return myRc;
}

/*****************************************************************************/
/* formatWinErrMsg                                                           */
/*****************************************************************************/
DWORD formatWinErrMsg(WCHAR *msg)
{
/*-- Local Variables  -------------------------------------------------------*/
  LPVOID lpMsgBuf = NULL;
  DWORD  rc;
/*-- Code -------------------------------------------------------------------*/
  msg[0] = L'\0';
  rc = GetLastError();
  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL,
                rc,
                MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
                (LPTSTR)&lpMsgBuf,
                0,
                NULL);
  if (lpMsgBuf != NULL) {
    wcscpy(msg, lpMsgBuf);
    LocalFree(lpMsgBuf);
  } else {
    msg[0] = L'\0';
  }

  return rc;
}

void startMultipart(LPSTR buf,
                    DWORD bufSize,
                    DWORD *pDataLength)
{
  memset(buf, 0, bufSize);
  *pDataLength = 0;
}

BOOL addFileToMultipart(LPSTR   buf,
                        DWORD   bufSize,
                        DWORD   *pDataLength,
                        LPCWSTR name,
                        LPCWSTR fileName,
                        LPCWSTR filePath,
                        LPCSTR  bndry)
{
  int          rc = 0;
  struct _stat statBuf;
  int          handle;
  int          bytesRead;
  char         buf2[2048];
  DWORD        bufOffset;

 /*-- Code -----------------------------------------------------------------*/

  bufOffset = *pDataLength;

  sprintf(buf2, "--%s\r\n", bndry);
  if (bufOffset + strlen(buf2) + 1 > bufSize) {
    return FALSE;
  }
  strcpy(buf + bufOffset, buf2);
  bufOffset += strlen(buf2);
  sprintf(buf2, "Content-Disposition: form-data; name=\"%ls\"; filename=\"%ls\"\r\n", name, fileName);
  if (bufOffset + strlen(buf2) + 1 > bufSize) {
    return FALSE;
  }
  strcpy(buf + bufOffset, buf2);
  bufOffset += strlen(buf2);
  strcpy(buf2, "Content-Type: application/octet-stream\r\n");
  if (bufOffset + strlen(buf2) + 1 > bufSize) {
    return FALSE;
  }
  strcpy(buf + bufOffset, buf2);
  bufOffset += strlen(buf2);
  strcpy(buf2, "Content-Transfer-Encoding: binary\r\n\r\n");
  if (bufOffset + strlen(buf2) + 1 > bufSize) {
    return FALSE;
  }
  strcpy(buf + bufOffset, buf2);
  bufOffset += strlen(buf2);

  if (filePath != NULL) {
    // Insert the contents of the file
    handle = _wopen(filePath, _O_RDONLY | _O_BINARY);
    if (handle != -1) {
      rc = _fstat(handle, &statBuf);
      if (rc != -1) {
        if (bufOffset + statBuf.st_size + 2 > bufSize) {
          LogMsg(TEXT("addFileToMultipart: File \"%s\" is too large for real time upload."), filePath);
          _close(handle);
          return FALSE;
        }
        bytesRead = _read(handle, buf + bufOffset, statBuf.st_size);
        if (bytesRead == -1) {
          LogMsg(TEXT("addFileToMultipart: Failure reading \"%s\"."), filePath);
          rc = bytesRead;
        } else {
          bufOffset += bytesRead;
          strcpy(buf + bufOffset, "\r\n");
          bufOffset += 2;
        }
      } else {
        LogMsg(TEXT("addFileToMultipart: Failure reading \"%s\"."), filePath);
        rc = -1;
      }
      _close(handle);
    } else {
      LogMsg(TEXT("addFileToMultipart: Could not open \"%s\" for read."), filePath);
      rc = -1;
    }
  }
  if (rc != 0) {
    return FALSE;
  }
  *pDataLength = bufOffset;
  return TRUE;
}

BOOL completeMultipart(LPSTR  buf,
                       DWORD  bufSize,
                       DWORD  *pDataLength,
                       LPCSTR bndry)
{
  char  buf2[2048];
  DWORD bufOffset;

  bufOffset = *pDataLength;

  sprintf(buf2, "--%s--\r\n", bndry);
  if (bufOffset + strlen(buf2) + 1 > bufSize) {
    return FALSE;
  }
  strcpy(buf + bufOffset, buf2);
  bufOffset += strlen(buf2);

  *pDataLength = bufOffset;
  return TRUE;
}

int postFileToServer(WCHAR *rtUploadServer,
                     WCHAR *rtUploadPort,
                     WCHAR *rtUploadScript,
                     BOOL  rtUploadSecure,
                     char  *fileBuf,
                     DWORD cgiDataLength,
                     char  *bndry,
                     WCHAR *outputFilePath)
{
  int       myRc = 0;
  HINTERNET hSession = NULL;
  HINTERNET hConnect = NULL;
  HINTERNET hOpenRequest = NULL;
  char      szRtUploadServer[512];
  char      szRtUploadScript[128];
  char      buf[4096];
  BOOL      result;
  DWORD     rc;
  DWORD     lenRead;
  DWORD     bytesRead = 0;
  wchar_t   msg[1024];
  DWORD     len;
  INTERNET_PORT serverPort = INTERNET_DEFAULT_HTTP_PORT;
  char      requestHeader[256]; 
  int       handle;
  DWORD     internetOpenFlags = INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD;
  int       retryCount;

  /* For debugging, write the contents of the multipart file to be uploaded */
  WCHAR     rtdebugDat[_MAX_PATH + 1];
  swprintf(rtdebugDat, LENGTH(rtdebugDat), TEXT("%s\\rtdebug.dat"), g_dataDir);
  handle = _wopen(rtdebugDat, O_RDWR | O_BINARY | O_CREAT | O_TRUNC, S_IREAD | S_IWRITE);
  if (handle != -1) {
    rc = _write(handle, fileBuf, cgiDataLength);
    if (rc != cgiDataLength) {
      LogMsg(TEXT("postFileToServer: Write to file \"%s\" failed."), rtdebugDat);
    }
    _close(handle);
  } else {
    LogMsg(TEXT("postFileToServer: Could not open \"%s\" for write."), rtdebugDat);
  }

  if ((rtUploadPort != NULL) && (rtUploadPort[0] != TEXT('\0'))) {
    serverPort = _wtoi(rtUploadPort);
  } else if (rtUploadSecure) {
    serverPort = INTERNET_DEFAULT_HTTPS_PORT;
  } else {
    serverPort = INTERNET_DEFAULT_HTTP_PORT;
  }

  hSession = InternetOpenA("HTTP/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
  if (hSession == NULL) {
    rc = formatWinErrMsg(msg);
    LogMsg(TEXT("postFileToServer: InternetOpen failed, rc = %lu, %s"), rc, msg);
    myRc = WIPA_GENERAL_FAILURE;
    goto endProc;
  }
  
  wcstombs(szRtUploadServer, rtUploadServer, sizeof szRtUploadServer);
  for (retryCount = 0;
       (hConnect == NULL) && (retryCount < 2);
       retryCount++) {
    if (retryCount) {
      /* If this is a connect retry, wait 3 seconds. */
      Sleep(3000);
    }
    hConnect = InternetConnectA(hSession,
                                szRtUploadServer,
                                serverPort,
                                NULL,
                                NULL,
                                INTERNET_SERVICE_HTTP,
                                0,
                                0);
  }
  if (hConnect == NULL) {
    rc = formatWinErrMsg(msg);
    LogMsg(TEXT("postFileToServer: InternetConnect failed, rc = %lu, %s"), rc, msg);
    myRc = WIPA_GENERAL_FAILURE;
    goto endProc;
  }

  if (rtUploadSecure) {
    internetOpenFlags |= INTERNET_FLAG_SECURE;
  }
  wcstombs(szRtUploadScript, rtUploadScript, sizeof szRtUploadScript);
  for (retryCount = 0;
       (hOpenRequest == NULL) && (retryCount < 2);
       retryCount++) {
    if (retryCount) {
      /* If this is an open request retry, wait 3 seconds. */
      Sleep(3000);
    }
    hOpenRequest = HttpOpenRequestA(hConnect,
                                    "POST",
                                    szRtUploadScript,
                                    NULL,
                                    NULL,
                                    NULL,
                                    internetOpenFlags,
                                    0);
  }
  if (hOpenRequest == NULL) {
    rc = formatWinErrMsg(msg);
    LogMsg(TEXT("postFileToServer: HttpOpenRequest failed, rc = %lu, %s"), rc, msg);
    myRc = WIPA_GENERAL_FAILURE;
    goto endProc;
  }

  sprintf(requestHeader, "Content-Type: multipart/form-data; boundary=%s\r\n", bndry);
  result = HttpAddRequestHeadersA(hOpenRequest,
                                  requestHeader,
                                  strlen(requestHeader),
                                  HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE);
  if (!result) {
    rc = formatWinErrMsg(msg);
    LogMsg(TEXT("postFileToServer: HttpAddRequestHeaders for Content-Type failed, rc = %lu, %s"), rc, msg);
    myRc = WIPA_GENERAL_FAILURE;
    goto endProc;
  }

  strcpy(requestHeader, "Connection: close\r\n");
  result = HttpAddRequestHeadersA(hOpenRequest,
                                  requestHeader,
                                  strlen(requestHeader),
                                  HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE);
  if (!result) {
    rc = formatWinErrMsg(msg);
    LogMsg(TEXT("postFileToServer: HttpAddRequestHeaders for Connection failed, rc = %lu, %s"), rc, msg);
    /* If this fails for some reason, we just continue without this header */
  }

  result = HttpSendRequestA(hOpenRequest, NULL, 0, fileBuf, cgiDataLength);
  if (!result) {
    rc = formatWinErrMsg(msg);
    LogMsg(TEXT("postFileToServer: HttpSendRequest failed, rc = %lu, %s"), rc, msg);
    myRc = WIPA_GENERAL_FAILURE;
    goto endProc;
  }

  len = sizeof buf;
  memset(buf, 0, sizeof buf);
  result = HttpQueryInfoA(hOpenRequest, HTTP_QUERY_STATUS_CODE, buf, &len, 0);
  if (!result) {
    rc = formatWinErrMsg(msg);
    LogMsg(TEXT("postFileToServer: HttpQueryInfo failed, rc = %lu, %s"), rc, msg);
    myRc = WIPA_GENERAL_FAILURE;
    goto endProc;
  }
  if (strcmp(buf, "200") != 0) {
    LogMsg(TEXT("postFileToServer: HttpQueryInfo status code: %hs"), buf);
    myRc = WIPA_GENERAL_FAILURE;
    goto endProc;
  }

  len = sizeof buf;
  memset(buf, 0, sizeof buf);
  result = TRUE;
  while (result) {
    result = InternetReadFile(hOpenRequest, (LPVOID)(buf + bytesRead), len - bytesRead, &lenRead);
    if (result) {
      if (lenRead == 0) {
        break;
      } else {
        bytesRead += lenRead;
      }
    }
  }
  if (result) {
    /* InternetReadFile can put extraneous garbage in the buffer past the end of the data read */
    buf[bytesRead] = '\0';
    if (bytesRead == 0) {
      LogMsg(TEXT("postFileToServer: Empty results file received from InternetReadFile."));
      myRc = WIPA_GENERAL_FAILURE;
      goto endProc;
    }
    /* Write the contents of the file */
    handle = _wopen(outputFilePath, O_RDWR | O_BINARY | O_CREAT | O_TRUNC, S_IREAD | S_IWRITE);
    if (handle != -1) {
      rc = _write(handle, buf, bytesRead);
      if (rc != bytesRead) {
        LogMsg(TEXT("postFileToServer: Write to file \"%s\" failed."), outputFilePath);
        myRc = WIPA_GENERAL_FAILURE;
        _close(handle);
        goto endProc;
      }
      _close(handle);
    } else {
      LogMsg(TEXT("postFileToServer: Could not open \"%s\" for write."), outputFilePath);
      myRc = WIPA_GENERAL_FAILURE;
      goto endProc;
    }
  } else {
    rc = formatWinErrMsg(msg);
    LogMsg(TEXT("postFileToServer: InternetReadFile failed, rc = %lu, %s"), rc, msg);
    myRc = WIPA_GENERAL_FAILURE;
    goto endProc;
  }

endProc:
  if (hOpenRequest != NULL) {
    InternetCloseHandle(hOpenRequest);
  }
  if (hConnect != NULL) {
    InternetCloseHandle(hConnect);
  }
  if (hSession != NULL) {
    InternetCloseHandle(hSession);
  }
  return myRc;
}

static BOOL uploadFile(WCHAR *rtUploadServer,
                       WCHAR *rtUploadPort,
                       WCHAR *rtUploadScript,
                       BOOL  rtUploadSecure,
                       WCHAR *fileName,
                       WCHAR *filePath)
{
  int   rc = 0;
  BOOL  myRc = TRUE;
  int   ft;
  DWORD realtimeSizeTotal = 0;
  DWORD realtimeBufSize = 0;
  char  *realtimeBuf = NULL;
  DWORD realtimeBufIndex = 0;
  int   mresultsRc = 0;
  DWORD charsCopied;
  WCHAR szRc[16];
  WCHAR mresultsIni[_MAX_PATH + 1];
  WCHAR mresultsFilename[_MAX_PATH + 1];
  WCHAR mresultsTable[256];
  WCHAR mresultsColumn[256];
  WCHAR mresultsMessage[1024];

  rc = includeFileForRealtime(filePath, &realtimeSizeTotal);
  if (realtimeSizeTotal == 0) {
    myRc = FALSE;
  } else {
    realtimeBufSize = realtimeSizeTotal + 4096; /* Allow 4096 bytes for additional headers */
    realtimeBuf = malloc(realtimeBufSize);
    if (realtimeBuf != NULL) {
      startMultipart(realtimeBuf, realtimeBufSize, &realtimeBufIndex);
    } else {
      myRc = FALSE;
    }
  }

  if (myRc) {
    if (!addFileToMultipart(realtimeBuf,
                            realtimeBufSize, 
                            &realtimeBufIndex,
                            fileName,
                            fileName,
                            filePath,
                            MULTIPART_BOUNDARY)) {
      myRc = FALSE;
    }
  }

  if (myRc) {
    if (completeMultipart(realtimeBuf,
                          realtimeBufSize,
                          &realtimeBufIndex,
                          MULTIPART_BOUNDARY)) {
      swprintf(mresultsIni, LENGTH(mresultsIni), TEXT("%s\\mresults.ini"), g_dataDir);
      if (fileExists(mresultsIni, &ft) && ft == TEXT('f')) { /* mresults.ini exists  */
        eraseFileWithErrorLogging(mresultsIni);
      }
      LogMsg(TEXT("uploadFile: Uploading file: %s to Server: %s  Port: %s  Script: %s"), fileName, rtUploadServer,rtUploadPort,rtUploadScript);
      rc = postFileToServer(rtUploadServer,
                            rtUploadPort,
                            rtUploadScript,
                            rtUploadSecure,
                            realtimeBuf,
                            realtimeBufIndex,
                            MULTIPART_BOUNDARY,
                            mresultsIni);
      if (rc == 0) {
        /* Analyze the mresults.ini file for upload results */
        charsCopied = GetPrivateProfileString(TEXT("RESULTS"),
                                              TEXT("rc1"),
                                              TEXT(""),
                                              szRc,
                                              LENGTH(szRc),
                                              mresultsIni);
        if (charsCopied > 0) {
          mresultsRc = _wtoi(szRc);
        } else {
          mresultsRc = -1;
        }
        if (mresultsRc != -1) {
          charsCopied = GetPrivateProfileString(TEXT("RESULTS"),
                                                TEXT("filename1"),
                                                TEXT(""),
                                                mresultsFilename,
                                                LENGTH(mresultsFilename),
                                                mresultsIni);
          if (charsCopied > 0) {
            if (_wcsicmp(fileName,
                         mresultsFilename) == 0) {
              if (mresultsRc == 0) {
                LogMsg(TEXT("uploadFile: File %s was uploaded."), fileName);
              } else {
                charsCopied = GetPrivateProfileString(TEXT("RESULTS"),
                                                      TEXT("table1"),
                                                      TEXT(""),
                                                      mresultsTable,
                                                      LENGTH(mresultsTable),
                                                      mresultsIni);
                charsCopied = GetPrivateProfileString(TEXT("RESULTS"),
                                                      TEXT("column1"),
                                                      TEXT(""),
                                                      mresultsColumn,
                                                      LENGTH(mresultsColumn),
                                                      mresultsIni);
                LogMsg(TEXT("uploadFile: Upload of file %s failed, rc = %d, table = \"%s\", column = \"%s\"."),
                       fileName,
                       mresultsRc,
                       mresultsTable,
                       mresultsColumn);
                myRc = FALSE;
              }
            }
          }
        }
        charsCopied = GetPrivateProfileString(TEXT("RESULTS"),
                                              TEXT("RC"),
                                              TEXT(""),
                                              szRc,
                                              LENGTH(szRc),
                                              mresultsIni);
        if (charsCopied > 0) {
          mresultsRc = _wtoi(szRc);
        } else {
          mresultsRc = 0;
        }
        if (mresultsRc > 0) {
          LogMsg(TEXT("uploadFile: Return code %s from real time upload server."), szRc);
          myRc = FALSE;
          charsCopied = GetPrivateProfileString(TEXT("RESULTS"),
                                                TEXT("MSG"),
                                                TEXT(""),
                                                mresultsMessage,
                                                LENGTH(mresultsMessage),
                                                mresultsIni);
          if (charsCopied > 0) {
            LogMsg(TEXT("uploadFile: Real time upload server message: %s"), mresultsMessage);
          }
        }
      } else { /* rc != 0, files could not be posted to server */
        myRc = FALSE;
        mresultsRc = -1;
      }
    } else { /* completeMultipart() failed */
      myRc = FALSE;
    }
  }
  /* If we allocated a real time buffer, free it. */
  if (realtimeBuf != NULL) {
    free(realtimeBuf);
  }
  return myRc;
}

/****************************************************************************/
/* includeFileForRealtime - Add a file to the list of files to be uploaded  */
/*                 via real time http, and add its size (plus a 1K header   */
/*                 overhead buffer) to the file size total.                 */
/* Inputs        : The file name to be uploaded via real time http, the     */
/*                 total size so far to which this file's size will be      */
/*                 added.                                                   */
/* Outputs       : Updates the total file size, returns 0 if successful,    */
/*                 WIPA_GENERAL_FAILURE otherwise.                          */
/****************************************************************************/
int includeFileForRealtime(WCHAR *filePath, DWORD *fileSizeTotal)
{
  int          rc;
  int          ft;
  struct _stat statBuf;

  if (fileExists(filePath, &ft) && ft == TEXT('f')) { /* the file exists      */
    rc = _wstat(filePath, &statBuf);
    if (rc == 0) {
      *fileSizeTotal += (statBuf.st_size + 1024); /* 1024 is to allow for headers */
    } else {
      LogMsg(TEXT("includeFileForRealtime: Size of file \"%s\" could not be determined."), filePath);
      return WIPA_GENERAL_FAILURE;
    }
  }
  return 0;
}

//----------------------------------------------------------------------------------
//
//
//----------------------------------------------------------------------------------
 int GetEmployeeCountryCode(WCHAR *countryCode)
 {
   //-- Local Variables --------------------------------------------------------
   
   #define  SERVERNAME TEXT("bluepages.ibm.com")
   #define PORTNUMBER LDAP_PORT
   
   LDAP      *ld;
   int        rc=0;
   
   WCHAR searchFilter[256];	
   WCHAR *searchFor[2];
   WCHAR searchAttr[128];
   LDAPMessage *srchRslt = NULL;
   LDAPMessage *ldapEntry = NULL;
   BerElement   *ber; 
   WCHAR         *a; 
   WCHAR         **vals; 
   int          i;
   WCHAR         *ptr;
   
   
  BOOL   regKeyOpened = FALSE;
  HKEY   hKey = NULL;
  DWORD  dataBufferSize, valueType;
  WCHAR  emailaddress[256];
  
   regKeyOpened = (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE,TEXT("SOFTWARE\\IGS\\C4EBReg\\user"),0,KEY_READ,&hKey));
   if (regKeyOpened) {
     dataBufferSize = LENGTH(emailaddress); 
     if (ERROR_SUCCESS != RegQueryValueEx(hKey,TEXT("IntranetID"),NULL,&valueType,(LPBYTE)emailaddress,&dataBufferSize)) {
       LogMsg(TEXT("GetEmployeeCountryCode: RegQueryValueEx for \"IntranetID\" failed"));
       countryCode[0] = TEXT('\0');
       rc = 1;
       goto endProc;
     }
   } else {
     LogMsg(TEXT("GetEmployeeCountryCode: RegOpenKeyEx for \"SOFTWARE\\IGS\\C4EBReg\\user\" failed"));
     countryCode[0] = TEXT('\0');
     rc = 1;
     goto endProc;
   }
   LogMsg(TEXT("Users Email Address: <%s>"),emailaddress);
   /* Get a handle to an LDAP connection. */
   if ( (ld = ldap_init( SERVERNAME, PORTNUMBER )) == NULL ) {
     rc = LdapGetLastError();
     LogMsg(TEXT("ldap_init error, rc=%d\n"), rc );
     rc = 1;
     goto endProc;
   }
   
   /* Bind to the server. */
   rc = ldap_simple_bind_s( ld, NULL, NULL );
   if ( rc != LDAP_SUCCESS ) {
     LogMsg(TEXT("ldap_simple_bind_s error: %s\n"), ldap_err2string( rc ) );
     ldap_unbind_s( ld );
     ld = NULL;
     rc = 2;
     goto endProc;
   }
   
   // search bluepages for the entry 
   wsprintf(searchFilter,TEXT("emailaddress=%s"),emailaddress);
   wsprintf(searchAttr,TEXT("employeecountrycode"));
   searchFor[0] = searchAttr;
   searchFor[1] = NULL;
   rc = ldap_search_s( ld, TEXT("ou=bluepages,o=ibm.com"), LDAP_SCOPE_SUBTREE, searchFilter, searchFor, 0, &srchRslt );
   if ( rc != LDAP_SUCCESS ) {
     LogMsg(TEXT("ldap_search_s for <%s> failed: %s\n"), searchFilter, ldap_err2string( rc ) );
     rc = 3;
     goto endProc;
   } /* endif */
   ldapEntry = ldap_first_entry( ld, srchRslt );
   if (ldapEntry == NULL) {
     LogMsg(TEXT("ldap_first_entry for <%s> returned null (No entry found)\n"), searchFilter);
     rc = 4;
     goto endProc;
   }
   
   /* Iterate through each attribute in the entry. */
   for ( a = ldap_first_attribute( ld, ldapEntry, &ber ); a != NULL; a = ldap_next_attribute( ld, ldapEntry, ber ) ) { 
     /* For each attribute, print the attribute name and values. */ 
     if ((vals = ldap_get_values( ld, ldapEntry, a)) != NULL ) { 
       for ( i = 0; vals[i] != NULL; i++ ) { 
         //LogMsg(TEXT("%s: %s\n"), a, vals[i] );
         if (wcscmp(a,TEXT("employeecountrycode")) == 0) {
           ptr = wcsstr(vals[i],TEXT("%"));
           if (ptr != NULL) {
             *ptr = '\0';
           }
           wcscpy(countryCode,vals[i]);
         }
       } 
       ldap_value_free( vals ); 
     } 
     ldap_memfree( a );
   } 

   
endProc:   
   if (ld != NULL) { ldap_unbind_s( ld ); }
   if (srchRslt != NULL) { ldap_msgfree(srchRslt); }
     
   return rc;
 }


/****************************************************************************/
/* initUsNamesAndValues: Initialize the names and corresponding values from */
/*                 the registry for all Source-id "user" variables.  These  */
/*                 are the predefined variables that represent the data     */
/*                 entered via the Registration Tool's user interface.  The */
/*                 values we are setting here (if any) are those entered by */
/*                 the user the last time the system was registered.        */
/* Inputs        :                                                          */
/* Outputs       : return code, 0 (success), or WIPA_GENERAL_FAILURE        */
/****************************************************************************/
int initUsNamesAndValues(void)
{
  int    rc = 0;
  struct variableItem *variPtr;
  WCHAR  userid[100];
  WCHAR  geography[128];
  WCHAR  jobRole[128];
  WCHAR  workstationUse[128];
  WCHAR  workstationUseAbbrev[128];
  BOOL   regKeyOpened = FALSE;
  HKEY   hKey = NULL;
  DWORD  dataBufferSize, valueType;

  regKeyOpened = (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                                                TEXT("SOFTWARE\\IGS\\C4EBReg\\user"),
                                                0,
                                                KEY_READ,
                                                &hKey));

  clearItemQueueNamesAndValues(&firstUsItem);

  variPtr = &firstUsItem;
  if (regKeyOpened) {
    dataBufferSize = sizeof userid; /* set the size of the data buffer */
    if (ERROR_SUCCESS != RegQueryValueEx(hKey,
                                         TEXT("IntranetID"),
                                         NULL,
                                         &valueType,
                                         (LPBYTE)userid,
                                         &dataBufferSize)) {
      userid[0] = TEXT('\0');
    }
  } else {
    userid[0] = TEXT('\0');
  }
  rc = insertItemQueueNameAndValue(variPtr,
                                   USE_CURRENT,
                                   TEXT("IntranetID"),
                                   userid,
                                   0,
                                   NULL,
                                   0);
  if (rc != 0) {
    goto ExitinitUsNamesAndValues;
  }

  if (regKeyOpened) {
    dataBufferSize = sizeof geography; /* set the size of the data buffer */
    if (ERROR_SUCCESS != RegQueryValueEx(hKey,
                                         TEXT("Geography"),
                                         NULL,
                                         &valueType,
                                         (LPBYTE)geography,
                                         &dataBufferSize)) {
      geography[0] = TEXT('\0');
    }
  } else {
    geography[0] = TEXT('\0');
  }
  rc = insertItemQueueNameAndValue(variPtr,
                                   INSERT_AFTER_CURRENT,
                                   TEXT("Geography"),
                                   geography,
                                   0,
                                   NULL,
                                   0);
  if (rc == 0) {
    variPtr = variPtr->pNextItem;
  } else {
    goto ExitinitUsNamesAndValues;
  }

  if (regKeyOpened) {
    dataBufferSize = sizeof jobRole; /* set the size of the data buffer */
    if (ERROR_SUCCESS != RegQueryValueEx(hKey,
                                         TEXT("JobRole"),
                                         NULL,
                                         &valueType,
                                         (LPBYTE)jobRole,
                                         &dataBufferSize)) {
      jobRole[0] = TEXT('\0');
    }
  } else {
    jobRole[0] = TEXT('\0');
  }
  rc = insertItemQueueNameAndValue(variPtr,
                                   INSERT_AFTER_CURRENT,
                                   TEXT("JobRole"),
                                   jobRole,
                                   0,
                                   NULL,
                                   0);
  if (rc == 0) {
    variPtr = variPtr->pNextItem;
  } else {
    goto ExitinitUsNamesAndValues;
  }

// --- workstationUse 
  if (regKeyOpened) {
    dataBufferSize = sizeof workstationUse; /* set the size of the data buffer */
    if (ERROR_SUCCESS != RegQueryValueEx(hKey,
                                         TEXT("WorkstationUse"),
                                         NULL,
                                         &valueType,
                                         (LPBYTE)workstationUse,
                                         &dataBufferSize)) {
      workstationUse[0] = TEXT('\0');
    }
  } else {
    workstationUse[0] = TEXT('\0');
  }
  rc = insertItemQueueNameAndValue(variPtr,
                                   INSERT_AFTER_CURRENT,
                                   TEXT("WorkstationUse"),
                                   workstationUse,
                                   0,
                                   NULL,
                                   0);
  if (rc == 0) {
    variPtr = variPtr->pNextItem;
  } else {
    goto ExitinitUsNamesAndValues;
  }

// --- workstationUseAbbrev
  if (regKeyOpened) {
    dataBufferSize = sizeof workstationUseAbbrev; /* set the size of the data buffer */
    if (ERROR_SUCCESS != RegQueryValueEx(hKey,
                                         TEXT("WorkstationUseAbbrev"),
                                         NULL,
                                         &valueType,
                                         (LPBYTE)workstationUseAbbrev,
                                         &dataBufferSize)) {
      workstationUseAbbrev[0] = TEXT('\0');
    }
  } else {
    workstationUseAbbrev[0] = TEXT('\0');
  }
  rc = insertItemQueueNameAndValue(variPtr,
                                   INSERT_AFTER_CURRENT,
                                   TEXT("WorkstationUseAbbrev"),
                                   workstationUseAbbrev,
                                   0,
                                   NULL,
                                   0);
  if (rc == 0) {
    variPtr = variPtr->pNextItem;
  } else {
    goto ExitinitUsNamesAndValues;
  }
  
  
  
  
ExitinitUsNamesAndValues:
  if (regKeyOpened) {
    RegCloseKey(hKey);
  }
  return rc;
}

/****************************************************************************/
/* initBiNamesAndValues: Initialize the names and corresponding values from */
/*                 the registry for all source-id "bios" variables.         */
/* Outputs       : return code, 0 (success), or WIPA_GENERAL_FAILURE        */
/****************************************************************************/
int initBiNamesAndValues(void)
{
  int    rc = 0;
  struct variableItem *variPtr;
  WCHAR  machineType[2048] = TEXT("");
  WCHAR  machineModel[2048] = TEXT("");
  WCHAR  machineSerial[2048] = TEXT("");
  BOOL   regKeyOpened = FALSE;
  HKEY   hKey = NULL;
  DWORD  dataBufferSize, valueType;

  regKeyOpened = (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                                                TEXT("SOFTWARE\\IGS\\C4EBReg\\bios"),
                                                0,
                                                KEY_READ,
                                                &hKey));

  clearItemQueueNamesAndValues(&firstBiItem);

  variPtr = &firstBiItem;
  if (regKeyOpened) {
    dataBufferSize = sizeof machineType; /* set the size of the data buffer */
    if (ERROR_SUCCESS != RegQueryValueEx(hKey,
                                         TEXT("MachineType"),
                                         NULL,
                                         &valueType,
                                         (LPBYTE)machineType,
                                         &dataBufferSize)) {
      machineType[0] = TEXT('\0');
    }
  } else {
    machineType[0] = TEXT('\0');
  }
  rc = insertItemQueueNameAndValue(variPtr,
                                   USE_CURRENT,
                                   TEXT("MachineType"),
                                   machineType,
                                   0,
                                   NULL,
                                   0);
  if (rc != 0) {
    goto ExitinitBiNamesAndValues;
  }

  if (regKeyOpened) {
    dataBufferSize = sizeof machineModel; /* set the size of the data buffer */
    if (ERROR_SUCCESS != RegQueryValueEx(hKey,
                                         TEXT("MachineModel"),
                                         NULL,
                                         &valueType,
                                         (LPBYTE)machineModel,
                                         &dataBufferSize)) {
      machineModel[0] = TEXT('\0');
    }
  } else {
    machineModel[0] = TEXT('\0');
  }
  rc = insertItemQueueNameAndValue(variPtr,
                                   INSERT_AFTER_CURRENT,
                                   TEXT("MachineModel"),
                                   machineModel,
                                   0,
                                   NULL,
                                   0);
  if (rc == 0) {
    variPtr = variPtr->pNextItem;
  } else {
    goto ExitinitBiNamesAndValues;
  }

  if (regKeyOpened) {
    dataBufferSize = sizeof machineSerial; /* set the size of the data buffer */
    if (ERROR_SUCCESS != RegQueryValueEx(hKey,
                                         TEXT("MachineSerial"),
                                         NULL,
                                         &valueType,
                                         (LPBYTE)machineSerial,
                                         &dataBufferSize)) {
      machineSerial[0] = TEXT('\0');
    }
  } else {
    machineSerial[0] = TEXT('\0');
  }
  rc = insertItemQueueNameAndValue(variPtr,
                                   INSERT_AFTER_CURRENT,
                                   TEXT("MachineSerial"),
                                   machineSerial,
                                   0,
                                   NULL,
                                   0);
  if (rc == 0) {
    variPtr = variPtr->pNextItem;
  } else {
    goto ExitinitBiNamesAndValues;
  }

ExitinitBiNamesAndValues:
  if (regKeyOpened) {
    RegCloseKey(hKey);
  }
  return rc;
}

/****************************************************************************/
/* initBpNamesAndValues: Initialize the names and corresponding values from */
/*                 the registry for all source-id "bluepages" variables.    */
/* Outputs       : return code, 0 (success), or WIPA_GENERAL_FAILURE        */
/****************************************************************************/
int initBpNamesAndValues(void)
{
  int    rc = 0;
  struct variableItem *variPtr;
  WCHAR  uid[2048] = TEXT("");
  WCHAR  notesEmail[2048] = TEXT("");
  WCHAR  dept[2048] = TEXT("");
  BOOL   regKeyOpened = FALSE;
  HKEY   hKey = NULL;
  DWORD  dataBufferSize, valueType;

  regKeyOpened = (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                                                TEXT("SOFTWARE\\IGS\\C4EBReg\\bluepages"),
                                                0,
                                                KEY_READ,
                                                &hKey));

  clearItemQueueNamesAndValues(&firstBpItem);

  variPtr = &firstBpItem;
  if (regKeyOpened) {
    dataBufferSize = sizeof uid; /* set the size of the data buffer */
    if (ERROR_SUCCESS != RegQueryValueEx(hKey,
                                         TEXT("uid"),
                                         NULL,
                                         &valueType,
                                         (LPBYTE)uid,
                                         &dataBufferSize)) {
      uid[0] = TEXT('\0');
    }
  } else {
    uid[0] = TEXT('\0');
  }
  rc = insertItemQueueNameAndValue(variPtr,
                                   USE_CURRENT,
                                   TEXT("uid"),
                                   uid,
                                   0,
                                   NULL,
                                   0);
  if (rc != 0) {
    goto ExitinitBpNamesAndValues;
  }

  if (regKeyOpened) {
    dataBufferSize = sizeof notesEmail; /* set the size of the data buffer */
    if (ERROR_SUCCESS != RegQueryValueEx(hKey,
                                         TEXT("notesEmail"),
                                         NULL,
                                         &valueType,
                                         (LPBYTE)notesEmail,
                                         &dataBufferSize)) {
      notesEmail[0] = TEXT('\0');
    }
  } else {
    notesEmail[0] = TEXT('\0');
  }
  rc = insertItemQueueNameAndValue(variPtr,
                                   INSERT_AFTER_CURRENT,
                                   TEXT("notesEmail"),
                                   notesEmail,
                                   0,
                                   NULL,
                                   0);
  if (rc == 0) {
    variPtr = variPtr->pNextItem;
  } else {
    goto ExitinitBpNamesAndValues;
  }

  if (regKeyOpened) {
    dataBufferSize = sizeof dept; /* set the size of the data buffer */
    if (ERROR_SUCCESS != RegQueryValueEx(hKey,
                                         TEXT("dept"),
                                         NULL,
                                         &valueType,
                                         (LPBYTE)dept,
                                         &dataBufferSize)) {
      dept[0] = TEXT('\0');
    }
  } else {
    dept[0] = TEXT('\0');
  }
  rc = insertItemQueueNameAndValue(variPtr,
                                   INSERT_AFTER_CURRENT,
                                   TEXT("dept"),
                                   dept,
                                   0,
                                   NULL,
                                   0);
  if (rc == 0) {
    variPtr = variPtr->pNextItem;
  } else {
    goto ExitinitBpNamesAndValues;
  }

ExitinitBpNamesAndValues:
  if (regKeyOpened) {
    RegCloseKey(hKey);
  }
  return rc;
}

/****************************************************************************/
/* initSyNamesAndValues: Initialize the names and corresponding values from */
/*                 the registry for all source-id "system" variables.       */
/* Outputs       : return code, 0 (success), or WIPA_GENERAL_FAILURE        */
/****************************************************************************/
int initSyNamesAndValues(void)
{
  int    rc = 0;
  struct variableItem *variPtr;
  WCHAR  computerName[2048] = TEXT("");
  WCHAR  hostName[2048] = TEXT("");
  WCHAR  opsysName[2048] = TEXT("");
  BOOL   regKeyOpened = FALSE;
  HKEY   hKey = NULL;
  DWORD  dataBufferSize, valueType;

  regKeyOpened = (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                                                TEXT("SOFTWARE\\IGS\\C4EBReg\\system"),
                                                0,
                                                KEY_READ,
                                                &hKey));

  clearItemQueueNamesAndValues(&firstSyItem);

  variPtr = &firstSyItem;
  if (regKeyOpened) {
    dataBufferSize = sizeof computerName; /* set the size of the data buffer */
    if (ERROR_SUCCESS != RegQueryValueEx(hKey,
                                         TEXT("ComputerName"),
                                         NULL,
                                         &valueType,
                                         (LPBYTE)computerName,
                                         &dataBufferSize)) {
      computerName[0] = TEXT('\0');
    }
  } else {
    computerName[0] = TEXT('\0');
  }
  rc = insertItemQueueNameAndValue(variPtr,
                                   USE_CURRENT,
                                   TEXT("ComputerName"),
                                   computerName,
                                   0,
                                   NULL,
                                   0);
  if (rc != 0) {
    goto ExitinitSyNamesAndValues;
  }

  if (regKeyOpened) {
    dataBufferSize = sizeof hostName; /* set the size of the data buffer */
    if (ERROR_SUCCESS != RegQueryValueEx(hKey,
                                         TEXT("HostName"),
                                         NULL,
                                         &valueType,
                                         (LPBYTE)hostName,
                                         &dataBufferSize)) {
      hostName[0] = TEXT('\0');
    }
  } else {
    hostName[0] = TEXT('\0');
  }
  rc = insertItemQueueNameAndValue(variPtr,
                                   INSERT_AFTER_CURRENT,
                                   TEXT("HostName"),
                                   hostName,
                                   0,
                                   NULL,
                                   0);
  if (rc == 0) {
    variPtr = variPtr->pNextItem;
  } else {
    goto ExitinitSyNamesAndValues;
  }

  if (regKeyOpened) {
    dataBufferSize = sizeof opsysName; /* set the size of the data buffer */
    if (ERROR_SUCCESS != RegQueryValueEx(hKey,
                                         TEXT("OpsysName"),
                                         NULL,
                                         &valueType,
                                         (LPBYTE)opsysName,
                                         &dataBufferSize)) {
      opsysName[0] = TEXT('\0');
    }
  } else {
    opsysName[0] = TEXT('\0');
  }
  rc = insertItemQueueNameAndValue(variPtr,
                                   INSERT_AFTER_CURRENT,
                                   TEXT("OpsysName"),
                                   opsysName,
                                   0,
                                   NULL,
                                   0);
  if (rc == 0) {
    variPtr = variPtr->pNextItem;
  } else {
    goto ExitinitSyNamesAndValues;
  }

ExitinitSyNamesAndValues:
  if (regKeyOpened) {
    RegCloseKey(hKey);
  }
  return rc;
}

int removeLeadingAndTrailingSpaces(WCHAR *buffer)
{
  WCHAR *buffer2 = NULL;
  int   i = 0;
  int   len;

  if (buffer[0] == TEXT(' ')) {
    buffer2 = calloc(wcslen(buffer) + 1, sizeof(WCHAR));
    if (buffer2 != NULL) {
      wcscpy(buffer2, buffer);
      while (buffer2[i] == TEXT(' ')) {
        i++;
      }
      wcscpy(buffer, buffer2 + i);
      free(buffer2);
    }
  }
  len = wcslen(buffer);
  while ((len > 0) && (buffer[len - 1] == TEXT(' '))) {
    buffer[len - 1] = TEXT('\0');
    len--;
  }
  return len;
}

void allowRunOnBattery(int taskNumber)
{
  SHELLEXECUTEINFO sei;
  WCHAR            exportedXmlPath[_MAX_PATH + 1];
  WCHAR            importedXmlPath[_MAX_PATH + 1];
  WCHAR            parms[4096];
  int              ft;
  WCHAR            cmdExePath[_MAX_PATH + 1];
  FILE             *fp = NULL;
  FILE             *fp2 = NULL;
  char             buffer[1024];
  DWORD            dwExitCode;
  char             stringToReplace1[] = "<DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>\r\r\n";
  char             stringReplacement1[] = "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\r\n";
  char             stringToReplace2[] = "<StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>\r\r\n";
  char             stringReplacement2[] = "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\r\n";
  char             *stringStart;
  
  swprintf(exportedXmlPath, LENGTH(exportedXmlPath), TEXT("%s\\out.xml"), g_dataDir);
  swprintf(importedXmlPath, LENGTH(importedXmlPath), TEXT("%s\\in.xml"), g_dataDir);
  if (fileExists(exportedXmlPath, &ft) && ft == TEXT('f')) {
    eraseFileWithErrorLogging(exportedXmlPath);
  }
  if (fileExists(importedXmlPath, &ft) && ft == TEXT('f')) {
    eraseFileWithErrorLogging(importedXmlPath);
  }

  /* Run schtasks.exe to export the scheduled task to out.xml */
  wcscpy(cmdExePath, g_systemDirectory);
  if (!PathAppend(cmdExePath, TEXT("cmd.exe"))) {
    LogMsg(TEXT("allowRunOnBattery: Cannot set path to cmd.exe, the scheduled task cannot be modified."));
    return;
  }
  swprintf(parms,
           LENGTH(parms),
           TEXT("/C \"\"%s\" /Query /TN WIPA%d /XML >\"%s\"\""),
           g_schtasksExePath, taskNumber, exportedXmlPath);
  ZeroMemory(&sei, sizeof(SHELLEXECUTEINFO));
  sei.cbSize = sizeof(SHELLEXECUTEINFO);
  sei.fMask = SEE_MASK_FLAG_NO_UI | SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_DDEWAIT;
  sei.lpFile = cmdExePath;
  sei.lpParameters = parms;
  sei.lpDirectory = g_systemDirectory;
  sei.nShow = SW_HIDE;
  if (!ShellExecuteEx(&sei)) {
    LogMsg(TEXT("allowRunOnBattery: Could not run cmd.exe, could not modify scheduled task."));
    return;
  }
  WaitForSingleObject(sei.hProcess, INFINITE);
  if (GetExitCodeProcess(sei.hProcess, &dwExitCode)) {
    if (dwExitCode != 0) {
      CloseHandle(sei.hProcess);
      LogMsg(TEXT("allowRunOnBattery: Cmd.exe exit code = %lu, could not modify scheduled task."), dwExitCode);
      return;
    }
  }
  CloseHandle(sei.hProcess);

  /* Copy out.xml to in.xml, modifying the battery related values */
  if ((!(fileExists(exportedXmlPath, &ft) && ft == TEXT('f'))) || 
      (isZeroLengthFile(exportedXmlPath))) {
    LogMsg(TEXT("allowRunOnBattery: Task was not exported as xml, could not modify scheduled task."));
    return;
  }
  fp2 = _wfopen(importedXmlPath, TEXT("wb"));
  if (fp2 == NULL) {
    LogMsg(TEXT("allowRunOnBattery: Could not open %s for write."), importedXmlPath);
    return;
  }
  fp = _wfopen(exportedXmlPath, TEXT("rb"));
  if (fp == NULL) {
    LogMsg(TEXT("allowRunOnBattery: Could not open %s for read."), exportedXmlPath);
    return;
  }
  ZeroMemory(buffer, sizeof(buffer));
  while (fgets(buffer, LENGTH(buffer) - 1, fp)) {
    stringStart = strstr(buffer, stringToReplace1);
    if (stringStart != NULL) {
      strcpy(stringStart, stringReplacement1);
    } else {
      stringStart = strstr(buffer, stringToReplace2);
      if (stringStart != NULL) {
        strcpy(stringStart, stringReplacement2);
      }
    }
    fputs(buffer, fp2);
    ZeroMemory(buffer, sizeof(buffer));
  }
  fclose(fp2);
  fclose(fp);
  if ((!(fileExists(importedXmlPath, &ft) && ft == TEXT('f'))) || 
      (isZeroLengthFile(importedXmlPath))) {
    LogMsg(TEXT("allowRunOnBattery: Exported xml file could not be processed, could not modify scheduled task."));
  }

  /* Wait 1 second befor running schtasks.exe again */
  Sleep(1000);

  /* Run schtasks.exe to import the scheduled task from in.xml */
  swprintf(parms,
           LENGTH(parms),
           TEXT("/Create /TN WIPA%d /F /XML \"%s\""),
           taskNumber, importedXmlPath);
  ZeroMemory(&sei, sizeof(SHELLEXECUTEINFO));
  sei.cbSize = sizeof(SHELLEXECUTEINFO);
  sei.fMask = SEE_MASK_FLAG_NO_UI | SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_DDEWAIT;
  sei.lpFile = g_schtasksExePath;
  sei.lpParameters = parms;
  sei.lpDirectory = g_systemDirectory;
  sei.nShow = SW_HIDE;
  if (!ShellExecuteEx(&sei)) {
    LogMsg(TEXT("allowRunOnBattery: Could not run schtasks.exe, could not modify scheduled task."));
    return;
  }
  WaitForSingleObject(sei.hProcess, INFINITE);
  if (GetExitCodeProcess(sei.hProcess, &dwExitCode)) {
    if (dwExitCode != 0) {
      CloseHandle(sei.hProcess);
      LogMsg(TEXT("allowRunOnBattery: Schtasks.exe exit code = %lu, could not modify scheduled task."), dwExitCode);
      return;
    }
  }
  CloseHandle(sei.hProcess);
}

BOOL createBatFile(WCHAR *batPath, WCHAR *batData)
{
  int  ft;
  FILE *fp;

  if (fileExists(batPath, &ft) && ft == TEXT('f')) {
    eraseFileWithErrorLogging(batPath);
  }
  fp = _wfopen(batPath, TEXT("w"));
  if (fp == NULL) {
    LogMsg(TEXT("createBatFile: Could not open \"%s\" for write."), batPath);
    return FALSE;
  }
  if (EOF == fputws(batData, fp)) {
    fclose(fp);
    return FALSE;
  }
  fclose(fp);
  return TRUE;
}

BOOL productShouldBeDisplayed(WCHAR *publisher, WCHAR *displayName)
{
  WCHAR               szValue[2048];
  WCHAR               buf[2048];
  WCHAR               *tempPtr;
  WCHAR               *wcstokState = NULL;

  if (g_userPublisherExclude[0] != TEXT('\0')) {
    if (publisher[0] != TEXT('\0')) {
      wcscpy(szValue, publisher);
      CharLower(szValue);
      wcscpy(buf, g_userPublisherExclude);
      CharLower(buf);
      tempPtr = wcstok(buf, TEXT("|"), &wcstokState);
      while (tempPtr != NULL) {
        if (wcsstr(szValue, tempPtr) != NULL) { /* This publisher should be excluded from display */
          break;
        }
        tempPtr = wcstok(NULL, TEXT("|"), &wcstokState);
      }
      if (tempPtr != NULL) { /* This publisher should be excluded from display */
        return FALSE;
      }
    }
  } else if (g_userPublisherInclude[0] != TEXT('\0')) {
    if (publisher[0] == TEXT('\0')) {
      return FALSE;
    }
    wcscpy(szValue, publisher);
    CharLower(szValue);
    wcscpy(buf, g_userPublisherInclude);
    CharLower(buf);
    tempPtr = wcstok(buf, TEXT("|"), &wcstokState);
    while (tempPtr != NULL) {
      if (wcsstr(szValue, tempPtr) != NULL) {
        break;
      }
      tempPtr = wcstok(NULL, TEXT("|"), &wcstokState);
    }
    if (tempPtr == NULL) { /* This publisher should be excluded from display */
      return FALSE;
    }
  }
  if (g_userDisplayNameExclude[0] != TEXT('\0')) {
    wcscpy(szValue, displayName);
    CharLower(szValue);
    wcscpy(buf, g_userDisplayNameExclude);
    CharLower(buf);
    tempPtr = wcstok(buf, TEXT("|"), &wcstokState);
    while (tempPtr != NULL) {
      if (wcsstr(szValue, tempPtr) != NULL) { /* This display name should be excluded from display */
        break;
      }
      tempPtr = wcstok(NULL, TEXT("|"), &wcstokState);
    }
    if (tempPtr != NULL) { /* This display name should be excluded from display */
      return FALSE;
    }
  } else if (g_userDisplayNameInclude[0] != TEXT('\0')) {
    wcscpy(szValue, displayName);
    CharLower(szValue);
    wcscpy(buf, g_userDisplayNameInclude);
    CharLower(buf);
    tempPtr = wcstok(buf, TEXT("|"), &wcstokState);
    while (tempPtr != NULL) {
      if (wcsstr(szValue, tempPtr) != NULL) {
        break;
      }
      tempPtr = wcstok(NULL, TEXT("|"), &wcstokState);
    }
    if (tempPtr == NULL) { /* This display name should be excluded from display */
      return FALSE;
    }
  }
  return TRUE;
}

void preserveOutputFiles(int numberOfFiles)
{
  int   i;
  int   ft;
  WCHAR fpath1[_MAX_PATH + 1];
  WCHAR fpath2[_MAX_PATH + 1];

  if (numberOfFiles >= 1) {
    /* First get rid of higher numbered files if the number of files to preserve is lower than it was previously */
    for (i = numberOfFiles + 1; i <= 1000; i++) {
      swprintf(fpath2, LENGTH(fpath2), TEXT("%s.%d"), g_uninOutput, i);
      if (fileExists(fpath2, &ft) && ft == TEXT('f')) { /* the file exists */
        eraseFileWithErrorLogging(fpath2);
      } else {
        /* Stop once we get to a file which does not exist */
        break;
      }
    }
    /* Now erase the highest numbered file  - the oldest of the ones we have remaining */
    swprintf(fpath2, LENGTH(fpath2), TEXT("%s.%d"), g_uninOutput, numberOfFiles);
    if (fileExists(fpath2, &ft) && ft == TEXT('f')) { /* the file exists */
      eraseFileWithErrorLogging(fpath2);
    }
    /* rename each remaining file to the next higher number */
    for (i = numberOfFiles - 1; i > 0; i--) {
      wcscpy(fpath1, fpath2);
      swprintf(fpath2, LENGTH(fpath2), TEXT("%s.%d"), g_uninOutput, i);
      if (fileExists(fpath2, &ft) && ft == TEXT('f')) { /* the file exists */
        renameFileWithErrorLogging(fpath2, fpath1);
      }
    }
    /* Rename the current output file */
    renameFileWithErrorLogging(g_uninOutput, fpath2);
  }
}

 
/*****************************************************************************/
/* GetPgmVersion                                                             */
/*****************************************************************************/
int GetPgmVersion(char *pgmName, WCHAR *pgmVersion)
{
/*-- Local Variables   ------------------------------------------------------*/
 int rc = 0;
 LPVOID        lpMsgBuf;
 char verBuf[500];
 BOOL flag;
 VS_FIXEDFILEINFO *version;
 UINT len;
 WCHAR wPgmName[PATH_MAX + 1];
/*-- Code -------------------------------------------------------------------*/
 mbstowcs(wPgmName,pgmName,sizeof(wPgmName)); 
 flag = GetFileVersionInfo(wPgmName, (DWORD)0, (DWORD)sizeof(verBuf), (VOID *)verBuf);
 if (flag == TRUE) {
   len = sizeof(version);
   flag = VerQueryValue((VOID *)verBuf, L"\\", (VOID *)&version, &len);
   if (flag == TRUE) {
     swprintf(pgmVersion, 20, TEXT("%hu.%hu.%hu.%hu"), 
       HIWORD(version->dwFileVersionMS),
       LOWORD(version->dwFileVersionMS),
       HIWORD(version->dwFileVersionLS),
       LOWORD(version->dwFileVersionLS)
     );
   } /* endif */
 } /* endif */
 if (flag == FALSE) {
  FormatMessage(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL,
      GetLastError(),
      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      (LPTSTR) &lpMsgBuf,
      0,
      NULL);
  fprintf(stderr,"Unable to determine the version of %s. %s",pgmName,lpMsgBuf);
  LocalFree( lpMsgBuf );
  rc = 1;
  wcscpy(pgmVersion,TEXT("00.00"));
 } //endif

 return rc;
}

