TARGET := iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = iosvuln_extract
iosvuln_extract_FILES = Tweak.xm
iosvuln_extract_FRAMEWORKS = Foundation
iosvuln_extract_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
