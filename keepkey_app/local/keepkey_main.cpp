#include <assert.h>
#include <stdio.h>

#include "bitcoin.h"


/*
 * Performs user prompting, etc. to make and confirm mnemonic.
 */
const char* get_mnemonic() {

    char answer = 'n';
    const char* mnemonic = NULL;


    do {
        /*
         * Generate seed and wait for user affirmation.
         */
        mnemonic = cd::make_mnemonic();

        assert(mnemonic != 0);

        printf("Generated seed: \"%s\"\n", mnemonic);
        printf("    Is this OK? y/n: ");
        scanf("%c", &answer);
    } while (answer != 'y');

    printf("mnemonic CONFIRMED.\n");

    return mnemonic;
}

int main(int argc, char *argv[]) {

    printf("Making seed ...\n");
    const char* mnemonic = get_mnemonic();

    return 0;
}
