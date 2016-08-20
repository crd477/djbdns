/* cribbed from:
 https://msdn.microsoft.com/en-us/library/windows/desktop/aa365968%28v=vs.85%29.aspx
 */
#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

extern char *dns_winresolv() {

  FIXED_INFO *pFixedInfo;
  ULONG ulOutBufLen;
  DWORD dwRetVal;
  IP_ADDR_STRING *pIPAddr;
  char *r;

  pFixedInfo = (FIXED_INFO *)MALLOC(sizeof(FIXED_INFO));
  if (pFixedInfo == NULL) {
    return NULL;
  }
  ulOutBufLen = sizeof(FIXED_INFO);

  /* Make an initial call to GetNetworkParams to get
   the necessary size into the ulOutBufLen variable */
  if (GetNetworkParams(pFixedInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
    FREE(pFixedInfo);
    pFixedInfo = (FIXED_INFO *)MALLOC(ulOutBufLen);
    if (pFixedInfo == NULL) {
      return NULL;
    }
  }

  /* NOTE: this logic is a bit flaky.  We pick the last IP in the list
   * because I've seen nameservers from other network profiles still appear in
   * the results from GetNetworkParams().  We make the assumption here that the
   * last one is always valid.
  */
  if (dwRetVal = GetNetworkParams(pFixedInfo, &ulOutBufLen) == NO_ERROR) {
    r = pFixedInfo->DnsServerList.IpAddress.String;
    pIPAddr = pFixedInfo->DnsServerList.Next;
    while (pIPAddr) {
      if (pIPAddr->IpAddress.String)
        r = pIPAddr->IpAddress.String;
      pIPAddr = pIPAddr->Next;
    }
  } else {
    return NULL;
  }

  if (pFixedInfo)
    FREE(pFixedInfo);

  return r;
}
