#include <stdio.h>
#include <string.h>
#include "xprotect_sdk.h"
int main(void) {
    char hw[64]; memset(hw, 0, sizeof hw);
    XProtectGetCurrentHWID(hw, (int)sizeof hw);
    printf("%s\n", hw);
    return 0;
}
