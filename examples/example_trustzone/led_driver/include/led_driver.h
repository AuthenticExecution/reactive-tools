#ifndef LED_DRIVER_H
#define LED_DRIVER_H

#include <tee_internal_api.h>

#define LED_DRIVER_UUID \
	{ 0xb210f0df, 0x8a68, 0x4b24, { 0x88, 0x0a, 0x87, 0x13, 0x58, 0x6c, 0x4d, 0x10 } }
	
	
TEE_Result entry(void *session, uint32_t param_types, TEE_Param params[4]);
void find_input_func(uint16_t io_id, unsigned char* data);

void toggle_led(unsigned char* data);


#endif
