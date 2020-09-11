LIBUSB_SRC_DIR = ../libusb
EXCLUDED_FILES = hotplug.h libusbi.h version.h version_nano.h
LIBUSB_SRC = $(wildcard $(LIBUSB_SRC_DIR)/*.c) $(wildcard $(LIBUSB_SRC_DIR)/*.h)
LIBUSB_DOC_SRC = $(filter-out $(addprefix $(LIBUSB_SRC_DIR)/,$(EXCLUDED_FILES)),$(LIBUSB_SRC))

docs: api-1.0

api-1.0: doxygen.cfg libusb.png $(LIBUSB_DOC_SRC)
	doxygen $<

docs-upload:
	scp -r api-1.0 web.sourceforge.net:/home/project-web/libusb/htdocs

clean:
	rm -rf api-1.0
