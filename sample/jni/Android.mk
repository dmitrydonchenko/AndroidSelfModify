LOCAL_PATH := $(call my-dir)
APP_PLATFORM := android-21

ifndef NDK_ROOT
include external/stlport/libstlport.mk
endif

include $(CLEAR_VARS)

LOCAL_MODULE    := MainActivity
LOCAL_SRC_FILES := MainActivity.cpp
LOCAL_LDLIBS := -llog

include $(BUILD_SHARED_LIBRARY)
