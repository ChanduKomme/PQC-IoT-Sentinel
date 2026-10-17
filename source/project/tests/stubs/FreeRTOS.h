#ifndef TEST_FREERTOS_H
#define TEST_FREERTOS_H
#include <stdint.h>
#include <stddef.h>
typedef uint32_t StackType_t;typedef int StaticTask_t;typedef int BaseType_t;typedef uint32_t TickType_t;
#define portTICK_PERIOD_MS 1u
#define pdMS_TO_TICKS(x) (x)
#define pdPASS 1
size_t xPortGetFreeHeapSize(void);size_t xPortGetMinimumEverFreeHeapSize(void);
#endif
