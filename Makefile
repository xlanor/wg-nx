ifeq ($(strip $(DEVKITPRO)),)
$(error "Please set DEVKITPRO in your environment")
endif

include $(DEVKITPRO)/libnx/switch_rules

TARGET		:=	libwireguard
BUILD		:=	build
SOURCES		:=	src library/crypto
INCLUDES	:=	include library/crypto src

ARCH		:=	-march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIC

CFLAGS		:=	-g -Wall -O2 -ffunction-sections $(ARCH)
CXXFLAGS	:=	$(CFLAGS) -fno-rtti -fno-exceptions

LIBDIRS		:=	$(PORTLIBS) $(LIBNX)

export OUTPUT	:=	$(CURDIR)/$(TARGET)
export VPATH	:=	$(foreach dir,$(SOURCES),$(CURDIR)/$(dir))
export DEPSDIR	:=	$(CURDIR)/$(BUILD)

CFILES		:=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(CURDIR)/$(dir)/*.c)))
OFILES		:=	$(CFILES:.c=.o)

export INCLUDE	:=	$(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir)) \
			$(foreach dir,$(LIBDIRS),-I$(dir)/include)

.PHONY: all clean

all: $(BUILD) $(OUTPUT).a

$(BUILD):
	@mkdir -p $@

$(OUTPUT).a: $(OFILES:%=$(BUILD)/%)
	@echo linking $(notdir $@)
	@rm -f $@
	@$(AR) -rc $@ $^

$(BUILD)/%.o: %.c | $(BUILD)
	@echo $(notdir $<)
	@$(CC) -MMD -MP -MF $(DEPSDIR)/$*.d $(CFLAGS) $(INCLUDE) -c $< -o $@

clean:
	@rm -rf $(BUILD) $(TARGET).a

-include $(wildcard $(BUILD)/*.d)
