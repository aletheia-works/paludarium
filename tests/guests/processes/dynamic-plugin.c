/* Loaded by the dynamic case: its relocations, its constructor and its
   thread-local variable. */
#include <stdio.h>
static __thread int count = 40;
static int started;
__attribute__((constructor)) static void start(void) { started = 1; }
int plugin_value(int more) {
    count += more;
    printf("plugin: started=%d count=%d\n", started, count);
    return count;
}
