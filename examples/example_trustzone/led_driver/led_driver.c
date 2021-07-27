#include <stdio.h>

#include <led_driver.h>
#include <authentic_execution.h>

void toggle_led(unsigned char* data){
	printf("\n");
	printf("Button is Pressed in TA1\n");
}

void find_input_func(uint16_t io_id, unsigned char* data){
	switch (io_id)
	{
		case 1:
			toggle_led(data);
		  	break;
	  
	  	default:
		  	break;
	}
}

TEE_Result entry(void *session, uint32_t param_types, TEE_Param params[4]){

	return TEE_SUCCESS;
}