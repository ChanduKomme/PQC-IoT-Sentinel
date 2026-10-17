#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Supply credentials at build time. The project build helpers read WIFI_SSID
 * and WIFI_PW from the local .env file and inject them as compiler defines.
 * Placeholder defaults intentionally fail rather than shipping real secrets.
 */
#ifndef WIFI_SSID
#define WIFI_SSID "REPLACE_WITH_WIFI_SSID"
#endif



#ifndef WIFI_PW
#define WIFI_PW "REPLACE_WITH_WIFI_PASSWORD"
#endif

void task_wifi(void *param);

#ifdef __cplusplus
}
#endif
