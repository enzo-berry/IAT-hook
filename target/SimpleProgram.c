#include <windows.h>
#include <stdio.h>

int main()
{
    printf("Press a key to show a messagebox\n");
    system("pause");
    MessageBoxA(NULL, "Hello World!", "Hello", MB_OK);
    printf("messagebox shown !\n");
    printf("Press key to exit\n");
    system("pause");
}

