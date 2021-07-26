#include <stdio.h>

//#include <tee_internal_api.h>

#include <button_driver.h>
#include <authentic_execution.h>

void find_input_func(uint16_t io_id, unsigned char* data){
	switch (io_id)
	{
	  	default:
		  	break;
	}
}

void button_pressed(void *session, uint32_t param_types, TEE_Param params[4]){
	struct aes_cipher *sess;
	sess = (struct aes_cipher *)session;
	uint16_t output_id = 0;
	handle_output(sess, output_id, param_types, params);
}

TEE_Result entry(void *session, uint32_t param_types, TEE_Param params[4]){
	struct aes_cipher *sess;
	sess = (struct aes_cipher *)session;
	printf("***************Button is Pressed inside entry func****************\n");
	//unsigned char data[16] = {0};
	//data[0]= 0x01;
	button_pressed(sess, param_types, params);
	return TEE_SUCCESS;
}



