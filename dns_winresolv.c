/* cribbed from:
   https://msdn.microsoft.com/en-us/library/windows/desktop/aa365968%28v=vs.85%29.aspx
*/
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>
#pragma comment(lib, "IPHLPAPI.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

/* Note: could also use malloc() and free() */

extern char *dns_winresolv() {

  FIXED_INFO *pFixedInfo;
  ULONG ulOutBufLen;
  DWORD dwRetVal;
  IP_ADDR_STRING *pIPAddr;
  char *x;

  pFixedInfo = (FIXED_INFO *)MALLOC(sizeof(FIXED_INFO));
  if (pFixedInfo == NULL) {
    return -1;
  }
  ulOutBufLen = sizeof(FIXED_INFO);

  /* Make an initial call to GetNetworkParams to get
     the necessary size into the ulOutBufLen variable */
  if (GetNetworkParams(pFixedInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
    FREE(pFixedInfo);
    pFixedInfo = (FIXED_INFO *)MALLOC(ulOutBufLen);
    if (pFixedInfo == NULL) {
      return -1;
    }
  }

  if (dwRetVal = GetNetworkParams(pFixedInfo, &ulOutBufLen) == NO_ERROR) {
    x = pFixedInfo->DnsServerList.IpAddress.String;
  } else {
    return 0;
  }

  if (pFixedInfo)
    FREE(pFixedInfo);

  return x;
}
