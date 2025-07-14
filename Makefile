# 编译器设置
CC := gcc
AS := gcc
LD := ld
ARCH := x86_64

# 编译选项
CFLAGS := -Wall -O2 -march=x86-64 -m64 -fno-builtin -fno-stack-protector \
          -fPIC -fPIE -nostdlib -ffreestanding
ASFLAGS := -m64 -nostdlib -Wa,--noexecstack
LDFLAGS := -m elf_x86_64 -nostdlib

# 文件自动收集
SRCS_C := $(wildcard *.c)
SRCS_S := $(wildcard *.S)
OBJS := $(patsubst %.c,%.o,$(SRCS_C)) $(patsubst %.S,%.o,$(SRCS_S))
TARGET := obhv.elf

# 默认目标
all: $(TARGET)

# 链接规则
$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $(OBJS)

# 编译C文件
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# 编译汇编文件
%.o: %.S
	$(AS) $(ASFLAGS) -c -o $@ $<

# 清理
clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean

