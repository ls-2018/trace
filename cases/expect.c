#include <stdio.h>
#include <stdbool.h>

#define unlikely(x) __builtin_expect(!!(x), 0)

int main(void) {
    bool enabled = false;

    if (unlikely(!enabled)) {
        printf("123\n");
    }
    printf("%ld\n",__builtin_expect(1, 0)  );

    return 0;
}
