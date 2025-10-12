#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main() {
    char secret_data[] = "This is a secret string in memory!";
    char url[] = "http://example.com/malware";
    char password[] = "SuperSecretPassword123";
    
    // Keep the program running for a while
    for (int i = 0; i < 30; i++) {
        sleep(1);
    }
    
    printf("[000000] Mal : Program finished.\n");
    return 0;
}
