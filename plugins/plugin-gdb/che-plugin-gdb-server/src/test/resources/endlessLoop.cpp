#include <iostream>
 
int main()
{
    int i = 0;
    int k = 100;
    while(true) {
        int temp = i;
        i = k;
        k = temp;
    }
}
