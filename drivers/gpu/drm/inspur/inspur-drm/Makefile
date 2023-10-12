ifneq ($(KERNELRELEASE),)

inspur-drm-y := inspur_drm_drv.o inspur_drm_de.o inspur_drm_vdac.o inspur_ttm.o inspur_drm_i2c.o

#obj-$(CONFIG_DRM_INSPUR) += inspur-drm.o
obj-m += inspur-drm.o


else
knv := $(shell uname -r)
KERNELDIR := /lib/modules/$(knv)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
endif
