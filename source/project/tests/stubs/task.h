#ifndef TEST_TASK_H
#define TEST_TASK_H
#include "FreeRTOS.h"
void vTaskDelay(uint32_t);void vTaskDelete(void *);void vTaskStartScheduler(void);
uint32_t xTaskGetTickCount(void);unsigned uxTaskGetStackHighWaterMark(void *);
int xTaskCreate(void (*)(void *),const char *,unsigned,void *,unsigned,void *);
void *xTaskCreateStatic(void (*)(void *),const char *,unsigned,void *,unsigned,StackType_t *,StaticTask_t *);
#endif
