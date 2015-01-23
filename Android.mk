ifneq ($(filter arm,$(TARGET_ARCH)),)

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	src/main.c \
	src/proc.c \
	src/unwind.c \
	src/util.c \
	src/xmalloc.c

LOCAL_CFLAGS := -Wall -Wno-switch -std=c99 -D_XOPEN_SOURCE=600 -D_BSD_SOURCE
LOCAL_MODULE := corehandler

LOCAL_SHARED_LIBRARIES := \
	libc

include $(BUILD_EXECUTABLE)

endif # arm in TARGET_ARCH

