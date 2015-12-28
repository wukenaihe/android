LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := hook

LOCAL_SRC_FILES := \
ARM.hpp\
Debug.cpp\
Debug.hpp\
CydiaSubstrate.h\
Hooker.cpp\
Log.hpp\
PosixMemory.cpp\
inline.cpp\
inline.h

LOCAL_SHARED_LIBRARIES := liblog libcutils
LOCAL_LDLIBS := -L$(SYSROOT)/usr/lib -llog

include $(BUILD_SHARED_LIBRARY)