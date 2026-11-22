TARGET := iosvuln_observe
TYPE := tweak
FILE := Tweak.x

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk

# rootless / Dopamine: set THEOS_PACKAGE_SCHEME=rootless when packaging
after-install::
	install.exec "killall -9 SpringBoard" || true
