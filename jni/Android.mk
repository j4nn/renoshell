LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_ARM_MODE := arm
LOCAL_CFLAGS := -O2 -DNDEBUG -D_GNU_SOURCE
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include/

LOCAL_MODULE    := bindershell
LOCAL_SRC_FILES := main.c getroot.c flex_array.c sid.c offsets.c client.c su98.c

include $(BUILD_EXECUTABLE)
