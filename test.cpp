#include "chpasswd.h"

int main()
{
    chpasswd("/tmp", "root", "thinker@123");
}