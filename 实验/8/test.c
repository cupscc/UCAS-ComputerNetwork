#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
int main()
{
    unsigned int a;
    char b[16] = "159.226.39.43";
    a = inet_addr(b);
    printf("%d\n", a);
}
