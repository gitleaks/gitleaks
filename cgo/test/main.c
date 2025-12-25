#include "../cgo.h"

#include <stdio.h>

int main(void) {
    char *err = NULL;

    uint64_t h = GitleaksCreateDefaultDetector(&err);
    if (h == 0) {
        fprintf(stderr, "CreateDefaultDetector failed: %s\n", err ? err : "(no error)");
        if (err) GitleaksFreeString(err);
        return 1;
    }

    const char *text = "export AWS_SECRET_ACCESS_KEY=abcd1234abcd1234abcd1234abcd1234abcd1234\n";
    char *json = GitleaksDetectString(h, text, "test.txt", &err);
    if (!json) {
        fprintf(stderr, "DetectString failed: %s\n", err ? err : "(no error)");
        if (err) GitleaksFreeString(err);
        GitleaksFreeDetector(h);
        return 2;
    }

    printf("%s\n", json);
    GitleaksFreeString(json);

    if (err) {
        // Should be NULL on success, but free defensively.
        GitleaksFreeString(err);
    }

    GitleaksFreeDetector(h);
    return 0;
}


