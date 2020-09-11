#include <stdio.h>
#include <string.h>
#include "libusb.h"
#include <pthread.h>


#include <stdlib.h>
#include <unistd.h>

#if 1 

int verbose = 0;
#define USB_VENDOR_ID 4489
#define USB_PRODUCT_ID 8980

#define RX_ADDR 0x81
#define TX_ADDR 0x01

void *thread_entry(void *arg)
{
	int ret, size;
	char buf[4096];
	libusb_device_handle *handle = (libusb_device_handle *)arg;
	
	while(1)
	{
		memset(buf, 0, sizeof(buf));
		ret = libusb_bulk_transfer(handle, RX_ADDR, buf, sizeof(buf), &size, 0);
		//ret = libusb_interrupt_transfer(handle, RX_ADDR, buf, sizeof(buf), &size, 3000);
		if(ret == 0)
		{
			buf[size] = '\0';
			printf("%s\r\n", buf);
			printf("recv size = %d\r\n", size);
		}
		else
		{
			
			printf("ret = %d\r\n", ret);
			
		}
		sleep(1);
	}
	return NULL;
}


int main(int argc, char *argv[])
{
	libusb_device **devs;
	struct libusb_device_descriptor desc;
	libusb_device_handle *handle = NULL;
//	char string[256];
	ssize_t cnt;
	int r, i;	
	

	if (argc > 1 && !strcmp(argv[1], "-v"))
		verbose = 1;

	r = libusb_init(NULL);
	if (r < 0)
		return r;

//	libusb_set_debug(ctx, 3);

	cnt = libusb_get_device_list(NULL, &devs);
	if (cnt < 0)
		return (int)cnt;

	for (i = 0; devs[i]; i++)	//print_device(devs[i]);
	{
		int ret = libusb_get_device_descriptor(devs[i], &desc);
		if (ret < 0) 
		{
			printf("failed to get device descriptor\r\n");
			return -1;
		}

		
		printf("Dev (bus %u, device %u): %04X - %04X\n",
		libusb_get_bus_number(devs[i]), libusb_get_device_address(devs[i]), desc.idVendor, desc.idProduct);  
#if 0
		if(desc.idVendor == USB_VENDOR_ID && desc.idProduct == USB_PRODUCT_ID)
		{
			ret = libusb_open(devs[i], &handle);
			if (LIBUSB_SUCCESS == ret) 
			{
				pthread_t thread = 0;
				pthread_create(&thread, NULL, thread_entry, (void *)handle); 
				pthread_detach(thread);

				printf("open success\r\n");

				int size = 0, j=0;
				while(j<10)
				{
					//ret = libusb_interrupt_transfer(handle, TX_ADDR, buf, sizeof(buf), &size, 0);
					ret = libusb_bulk_transfer(handle, TX_ADDR, buf, sizeof(buf), &size, 0);
					if(ret != 0)
					{
						printf("transfer fail error:%d\r\n", ret);
//						libusb_strerror(ret);
//						break;
					}
					printf("send size = %d\r\n", size);
					sleep(1);
					j++;
				}
				
			}
			else
			{
				printf("open fail  error:%d\r\n", ret);
			}
		}
#endif		
	}

#if 1
	handle = libusb_open_device_with_vid_pid(NULL, USB_VENDOR_ID, USB_PRODUCT_ID);
    if (handle == NULL) 
	{
        printf("cant't open device\r\n");
        goto error;
    } else 
	{
        printf("open device\r\n");
    }

	if(libusb_kernel_driver_active(handle, 0) ==1) 
	{
        printf("kernel driver active, detach it \r\n");

        if (libusb_detach_kernel_driver(handle, 0) == 0) 
		{
            printf("detached kernel driver\r\n");
        }
        else 
		{
            goto error;
        }
    }
	int ret;

	ret = libusb_claim_interface(handle, 0);
    if (ret < 0) 
	{
        printf("can't claim interface\r\n");
        goto error;
    } 
	else 
	{
        printf("claimed interface\r\n");
    }

	pthread_t thread = 0;
	pthread_create(&thread, NULL, thread_entry, (void *)handle); 
	pthread_detach(thread);

	printf("open success\r\n");
	
	int size = 0;
	char buf[4096] = "Nicholas";
	while(1)
	{
		//ret = libusb_interrupt_transfer(handle, TX_ADDR, buf, sizeof(buf), &size, 0);
		ret = libusb_bulk_transfer(handle, TX_ADDR, buf, sizeof(buf), &size, 0);
		if(ret != 0)
		{
			printf("transfer fail error:%d\r\n", ret);
//						libusb_strerror(ret);
//						break;
		}
		printf("send size = %d\r\n", size);
		sleep(1);
	}
error:

#endif
	
	if (handle)
		libusb_close(handle);

	libusb_free_device_list(devs, 1);

	libusb_exit(NULL);
	return 0;
}
#else

#endif





